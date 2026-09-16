rule Win_Trojan_Kitan_1
{
strings:
	$a0 = { 45e7abb80102b2808ec18ac8cd13803feb7411fec441cd135033c0e818005841cd13ebdf41cd13 }


condition:
	$a0
}