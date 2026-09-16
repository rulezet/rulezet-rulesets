rule Win_Trojan_Tolbuhin_2
{
strings:
	$a0 = { 2acd2180fa15751bb80903ba0000b901008d1e0001cd13 }


condition:
	$a0
}