rule Win_Trojan_Nado_1
{
strings:
	$a0 = { db0126835f1f00075b58cf3dcbbc7504bbcbbccf80fc1174bd80fc1274b853bb004b3bc3 }


condition:
	$a0
}