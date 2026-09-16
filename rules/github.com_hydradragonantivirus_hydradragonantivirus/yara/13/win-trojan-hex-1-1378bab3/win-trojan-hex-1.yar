rule Win_Trojan_Hex_1
{
strings:
	$a0 = { b90100b80103cd13bb0002ba8000b90900b80103cd13ba0001b90627c6064e0100 }


condition:
	$a0
}