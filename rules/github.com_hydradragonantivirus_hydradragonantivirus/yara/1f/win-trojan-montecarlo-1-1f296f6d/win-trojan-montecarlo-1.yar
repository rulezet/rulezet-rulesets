rule Win_Trojan_MonteCarlo_1
{
strings:
	$a0 = { 1801501e0e1fbf1801b9b305b233301547fec2e2f91fc3 }


condition:
	$a0
}