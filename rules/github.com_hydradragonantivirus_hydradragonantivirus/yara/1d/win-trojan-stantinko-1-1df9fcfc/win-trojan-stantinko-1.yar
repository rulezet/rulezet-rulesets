rule Win_Trojan_Stantinko_1
{
strings:
	$a0 = { 6661737420756178 }

	$a1 = { 2f6e6f74696669636174652e7068703f69643d }


condition:
	$a0 and $a1
}