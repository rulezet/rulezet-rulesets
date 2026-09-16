rule Win_Trojan_Crypt_199
{
strings:
	$a0 = { 68bab9f70a892c2481f4ffffffffe938faffff8d642404ff75f8e83903000081c410000000e8e0f7ffff8378 }


condition:
	$a0
}