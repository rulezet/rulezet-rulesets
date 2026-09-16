rule Win_Trojan_Crypt_125
{
strings:
	$a0 = { e800000000[0-20]83ea[0-20]8182??000000[0-20]97a1[0-30]81b2??000000 }


condition:
	$a0
}