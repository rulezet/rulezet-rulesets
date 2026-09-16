rule Win_Trojan_Trivial_322
{
strings:
	$a0 = { 3380ec3388263901b44eba356180ee60cd21721fb8423d2c4033d2b2ce83ea30cd2193b440b13a909033d2fec6cd21b44febddc32a2e632a }


condition:
	$a0
}