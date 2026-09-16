rule Win_Trojan_Trivial_24
{
strings:
	$a0 = { cd217301c3b80043ba9e00cd21b80143b100cd21b8013dcd2193b440b139ba0001cd21b43ecd }


condition:
	$a0
}