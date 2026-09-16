rule Win_Trojan_V1226B_1
{
strings:
	$a0 = { 8bf333c9b8400350334f22434348 }


condition:
	$a0
}