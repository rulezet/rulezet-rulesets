rule Win_Trojan_Stoned_36
{
strings:
	$a0 = { d0e80ac07408b40eb700cd10ebf1ebfeb80103cd13b80102b90700cd13eb5e }


condition:
	$a0
}