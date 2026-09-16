rule Win_Trojan_Sality_1052
{
strings:
	$a0 = { 5f83c70189d28a4405003007 }


condition:
	$a0
}