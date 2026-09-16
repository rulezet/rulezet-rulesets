rule Win_Trojan_Small_4500
{
strings:
	$a0 = { b8??560706352564450650e81b000000e82c00000003018d7604 }


condition:
	$a0
}