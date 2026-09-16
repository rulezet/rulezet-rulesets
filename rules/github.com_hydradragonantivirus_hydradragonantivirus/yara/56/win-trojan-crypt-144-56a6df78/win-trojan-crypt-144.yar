rule Win_Trojan_Crypt_144
{
strings:
	$a0 = { 81c1????????(01|29|31)(08|0a|0b|0e|0f)81e9[0-20]3b(c1|d1|d9|e9|f1|f9)0f82??ffffff }


condition:
	$a0
}