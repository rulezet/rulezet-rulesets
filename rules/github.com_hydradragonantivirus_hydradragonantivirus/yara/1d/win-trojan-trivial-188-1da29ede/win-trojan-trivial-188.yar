rule Win_Trojan_Trivial_188
{
strings:
	$a0 = { b44eba2001b92400cd21ba9e00b8023dcd219392fec6b440cd21b43ecd21 }


condition:
	$a0
}