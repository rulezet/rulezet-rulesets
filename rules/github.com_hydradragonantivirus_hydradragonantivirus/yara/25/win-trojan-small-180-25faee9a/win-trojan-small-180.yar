rule Win_Trojan_Small_180
{
strings:
	$a0 = { 427f2080ea41b6010e07bbf0022e031e0101b80102b90100cd1372a2b80103cd13729b8bd6e8 }


condition:
	$a0
}