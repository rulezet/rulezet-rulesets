rule Win_Trojan_Small_4497
{
strings:
	$a0 = { b8??560706352564450650e81d000000e8 }


condition:
	$a0
}