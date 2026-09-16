rule Win_Trojan_Small_4503
{
strings:
	$a0 = { b825260506352564450650e81d000000e8 }


condition:
	$a0
}