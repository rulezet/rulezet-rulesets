rule Win_Trojan_Trivial_470
{
strings:
	$a0 = { ba1e01cd21b8023dba9e00cd2193ba0001b440b123cd21b43ecd21c32a2e432a00 }


condition:
	$a0
}