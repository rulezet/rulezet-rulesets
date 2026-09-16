rule Win_Trojan_Crypt_137
{
strings:
	$a0 = { ba????????b900000001[0-130]0f014c24f8 }


condition:
	$a0
}