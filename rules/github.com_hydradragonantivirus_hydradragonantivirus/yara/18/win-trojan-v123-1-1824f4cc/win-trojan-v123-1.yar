rule Win_Trojan_V123_1
{
strings:
	$a0 = { b97b00f3a4bad400b41acd21ba7501b4 }


condition:
	$a0
}