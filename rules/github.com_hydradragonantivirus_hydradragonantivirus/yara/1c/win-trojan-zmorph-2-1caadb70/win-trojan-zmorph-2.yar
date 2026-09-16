rule Win_Trojan_ZMorph_2
{
strings:
	$a0 = { 81c83cdd2bb23563c2c9e0e77ec9d1622d0a3a63f2c9d1cbc239d2632acad1000ec9a2 }


condition:
	$a0
}