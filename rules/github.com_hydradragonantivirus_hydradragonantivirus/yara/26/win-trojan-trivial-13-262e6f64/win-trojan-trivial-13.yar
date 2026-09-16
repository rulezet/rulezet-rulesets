rule Win_Trojan_Trivial_13
{
strings:
	$a0 = { 43ba9e00cd21b80143b100cd21b43dcd2193b440b133ba0001cd21b43ecd21b44febd62a2e2a }


condition:
	$a0
}