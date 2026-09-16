rule Win_Trojan_Bancos_1479
{
strings:
	$a0 = { 627261646573636f2e636f6d00000000ffffffff070000005c62722e636d6400ffffffff0f000000554e4942414e43 }


condition:
	$a0
}