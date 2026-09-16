rule Win_Trojan_Milan_Naziskin_1
{
strings:
	$a0 = { cd2172c98bd8b80057cd2189160901890e0b01ba00 }


condition:
	$a0
}