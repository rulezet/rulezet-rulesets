rule Win_Trojan_ItaVir_2
{
strings:
	$a0 = { 5845894002b000884004 }


condition:
	$a0
}