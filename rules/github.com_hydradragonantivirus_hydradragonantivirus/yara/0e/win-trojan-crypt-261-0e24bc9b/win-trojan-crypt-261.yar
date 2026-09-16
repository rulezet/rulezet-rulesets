rule Win_Trojan_Crypt_261
{
strings:
	$a0 = { 81eee5b159720bcac1f90d81d640c2076ffecb81f8523e8bda0f85b607000070e09f7b4d81 }


condition:
	$a0
}