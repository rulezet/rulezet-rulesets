rule Win_Trojan_Evasor_4
{
strings:
	$a0 = { 8db648018bfee80300eb2290acf6d0fec8c0c804f6 }


condition:
	$a0
}