rule Win_Trojan_CMOS_3
{
strings:
	$a0 = { bf7d1e0789e3b90100ba8000b80102cd1381ff0101740bb90f00ba0001b80102cd7fea007c00 }


condition:
	$a0
}