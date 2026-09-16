rule Win_Trojan_Trivial_93
{
strings:
	$a0 = { 2a2e2a00b44efec6cd21b43cba9e00cd2193b440 }


condition:
	$a0
}