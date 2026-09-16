rule Win_Trojan_VGEN_714
{
strings:
	$a0 = { 174f01558bec1eb4002ea002008b5e128e5e1489072ea001008e5e108b5e0e89072ea004008e5e0c8b5e0a8907 }


condition:
	$a0
}