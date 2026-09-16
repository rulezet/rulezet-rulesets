rule Win_Trojan_Tongbot_1
{
strings:
	$a0 = { 2d2d2d74646f6e677364626f74312e3031b2e2cad4b0e6b7b4b5af7368656c6c2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d0d0a002d2d2d2dcdea }


condition:
	$a0
}