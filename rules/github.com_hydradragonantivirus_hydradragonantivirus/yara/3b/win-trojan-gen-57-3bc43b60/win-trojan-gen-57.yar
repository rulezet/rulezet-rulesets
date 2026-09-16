rule Win_Trojan_Gen_57
{
strings:
	$a0 = { 86008edbc606500700c606510700a33b }


condition:
	$a0
}