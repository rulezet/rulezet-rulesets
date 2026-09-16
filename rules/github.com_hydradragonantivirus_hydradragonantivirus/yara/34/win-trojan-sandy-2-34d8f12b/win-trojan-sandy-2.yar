rule Win_Trojan_Sandy_2
{
strings:
	$a0 = { 8b0e00008cdabe3c0032f22e310c03fe46505a468cda81fe5f057eef }


condition:
	$a0
}