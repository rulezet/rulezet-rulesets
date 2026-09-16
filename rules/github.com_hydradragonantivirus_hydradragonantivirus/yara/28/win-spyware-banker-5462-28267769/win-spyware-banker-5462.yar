rule Win_Spyware_Banker_5462
{
strings:
	$a0 = { f0ae5e76db2720a66dee10851dac352c5ef4b58bc88bf8cd729420f6bb70e1267245f8f822dc1d8fa5baf709a5a45a28ccf8a46a5c3eac6b8743211429b0e2be14cdaa4d0b433d4f20e2c6daa215 }


condition:
	$a0
}