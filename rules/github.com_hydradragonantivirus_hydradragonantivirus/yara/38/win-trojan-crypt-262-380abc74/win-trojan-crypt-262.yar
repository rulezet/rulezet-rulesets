rule Win_Trojan_Crypt_262
{
strings:
	$a0 = { 13c0e989ffffff1bc2c36959fce69179e1341a974ba7fa675c146611d89e01ec1baf8114 }


condition:
	$a0
}