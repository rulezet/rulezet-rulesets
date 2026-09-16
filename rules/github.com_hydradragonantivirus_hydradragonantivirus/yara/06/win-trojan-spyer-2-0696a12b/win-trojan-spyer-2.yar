rule Win_Trojan_Spyer_2
{
strings:
	$a0 = { 8b36010103f7fcf3a450c38b360101bf }


condition:
	$a0
}