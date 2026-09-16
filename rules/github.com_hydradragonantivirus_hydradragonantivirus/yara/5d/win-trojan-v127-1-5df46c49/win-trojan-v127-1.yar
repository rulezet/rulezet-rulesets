rule Win_Trojan_V127_1
{
strings:
	$a0 = { b97f00f3a4bad400b41acd21ba7901b1 }


condition:
	$a0
}