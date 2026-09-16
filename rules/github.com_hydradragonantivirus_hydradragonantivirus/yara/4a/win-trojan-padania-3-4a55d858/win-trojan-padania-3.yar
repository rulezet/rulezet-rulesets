rule Win_Trojan_Padania_3
{
strings:
	$a0 = { 550000000000ffff09030000cf030000110000000903 }


condition:
	$a0
}