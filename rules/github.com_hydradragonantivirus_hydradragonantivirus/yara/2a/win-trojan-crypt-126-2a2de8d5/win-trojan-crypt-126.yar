rule Win_Trojan_Crypt_126
{
strings:
	$a0 = { e800000000[0-10]8b1424[0-70]8180??000000????????97a1 }


condition:
	$a0
}