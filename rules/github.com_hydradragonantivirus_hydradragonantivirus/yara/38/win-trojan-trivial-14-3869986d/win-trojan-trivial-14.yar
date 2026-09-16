rule Win_Trojan_Trivial_14
{
strings:
	$a0 = { 2a00b80043ba9e00cd21b80143b100cd21b8013dcd2193b440b134ba0001cd21b43ecd21b44f }


condition:
	$a0
}