rule Win_Trojan_ANSI_Bomb90_1
{
strings:
	$a0 = { e660b080e66133d2b14432ed33db32c040408edb52cd265a5a83c244ebea }


condition:
	$a0
}