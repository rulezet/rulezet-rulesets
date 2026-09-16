rule Win_Trojan_Miny_3
{
strings:
	$a0 = { 2d0300a32c01c6062e0143b44033d2b92c01cd21b000e89400b440ba2b01b90400cd21b43ecd21 }


condition:
	$a0
}