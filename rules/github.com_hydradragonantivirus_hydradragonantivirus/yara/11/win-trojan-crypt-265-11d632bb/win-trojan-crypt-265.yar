rule Win_Trojan_Crypt_265
{
strings:
	$a0 = { 8bc3558bece966ffffff33f183ca236a400bc268000b000083f62f83f13a81fb }


condition:
	$a0
}