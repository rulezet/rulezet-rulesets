rule Win_Trojan_Trivial_204
{
strings:
	$a0 = { ba2201b44ecd217217ba9e00b8013dcd2193b440b92600ba0001cd21b43ecd21 }


condition:
	$a0
}