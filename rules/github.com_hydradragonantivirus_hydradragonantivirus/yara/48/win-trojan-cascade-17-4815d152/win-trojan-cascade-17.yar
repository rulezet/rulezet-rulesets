rule Win_Trojan_Cascade_17
{
strings:
	$a0 = { e800005b81eb32012ef6872b01018db74e0143bc85063134903124464c75f7 }


condition:
	$a0
}