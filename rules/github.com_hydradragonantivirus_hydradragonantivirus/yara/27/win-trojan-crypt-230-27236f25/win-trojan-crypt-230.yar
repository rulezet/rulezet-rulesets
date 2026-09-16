rule Win_Trojan_Crypt_230
{
strings:
	$a0 = { 6633c0740f7d106d8967306987761a5883631b08575783 }


condition:
	$a0
}