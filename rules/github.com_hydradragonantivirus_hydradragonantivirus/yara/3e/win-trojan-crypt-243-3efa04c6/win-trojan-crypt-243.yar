rule Win_Trojan_Crypt_243
{
strings:
	$a0 = { 6825c44a0083e00064ff306489208838c05060 }


condition:
	$a0
}