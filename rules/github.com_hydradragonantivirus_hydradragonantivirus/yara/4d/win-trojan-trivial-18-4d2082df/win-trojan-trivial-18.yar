rule Win_Trojan_Trivial_18
{
strings:
	$a0 = { cd217301c3b443ba9e00cd21b80143b100cd21b43dcd2193b440b134ba0001cd21b43ecd21eb }


condition:
	$a0
}