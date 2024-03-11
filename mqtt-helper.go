package mqtt_helper

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"time"
)

type PasswordEncryptor func(originalPassword string) (encryptedPassword string, err error)
type UsernameTransformer func(originalUsername string) (transformedUsername string, err error)

type NewMQTTClientOptions struct {
	UsernameTransformer   UsernameTransformer                 // optional, username transformer
	PasswordEncryptor     PasswordEncryptor                   // optional, password custom encryptor; default is no encrypt
	Brokers               []string                            // required, MQTT broker address
	ClientID              string                              // required, MQTT client ID
	Username              string                              // required, MQTT username
	Password              string                              // required, MQTT password
	ALPN                  []string                            // optional, MQTT ALPN
	ConnectionLostHandler func(client mqtt.Client, err error) // optional, connection lost handler
}

func NewHmacSha1Encryptor(key string) PasswordEncryptor {
	return func(originalPassword string) (encryptedPassword string, err error) {
		mac := hmac.New(sha1.New, []byte(key))
		mac.Write([]byte(originalPassword))
		return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
	}
}

func NewAwsIotUsernameTransformer(customAuthName string) UsernameTransformer {
	return func(originalUsername string) (string, error) {
		return fmt.Sprintf("%s?x-amz-customauthorizer-name=%s", originalUsername, customAuthName), nil
	}
}

func NewMQTTClient(opts *NewMQTTClientOptions) (*mqtt.Client, error) {
	if opts.UsernameTransformer == nil {
		opts.UsernameTransformer = func(originalUsername string) (string, error) {
			return originalUsername, nil
		}
	}
	if opts.PasswordEncryptor == nil {
		opts.PasswordEncryptor = func(originalPassword string) (encryptedPassword string, err error) {
			return originalPassword, nil
		}
	}

	username, err := opts.UsernameTransformer(opts.Username)
	if err != nil {
		return nil, err
	}
	password, err := opts.PasswordEncryptor(opts.Password)
	if err != nil {
		return nil, err
	}

	options := mqtt.NewClientOptions()
	options.SetClientID(opts.ClientID)
	options.SetMaxReconnectInterval(2 * time.Second)
	options.SetUsername(username)
	options.SetPassword(password)
	if opts.ALPN != nil {
		options.SetTLSConfig(&tls.Config{
			NextProtos: opts.ALPN,
		})
	}
	for _, broker := range opts.Brokers {
		options.AddBroker(broker)
	}
	options.SetConnectTimeout(10 * time.Second)
	options.SetConnectionLostHandler(opts.ConnectionLostHandler)

	client := mqtt.NewClient(options)
	token := client.Connect()
	token.Wait()
	err = token.Error()
	if err != nil {
		return nil, err
	} else {
		return &client, nil
	}
}

func Subscribe(client *mqtt.Client, topic string, qos byte, handler func(message mqtt.Message)) error {
	token := (*client).Subscribe(topic, qos, func(client mqtt.Client, msg mqtt.Message) {
		go handler(msg)
		msg.Ack()
	})
	token.Wait()
	return token.Error()
}

func Publish(client *mqtt.Client, topic string, qos byte, payload []byte) error {
	token := (*client).Publish(topic, qos, false, payload)
	token.Wait()
	return token.Error()
}
