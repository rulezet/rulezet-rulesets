rule Win_Trojan_Trivial_117
{
strings:
	$a0 = { ba1100b44ecd21ba9e00b43dcd2193b21b2a2e2a0087d1b440ebf1 }


condition:
	$a0
}