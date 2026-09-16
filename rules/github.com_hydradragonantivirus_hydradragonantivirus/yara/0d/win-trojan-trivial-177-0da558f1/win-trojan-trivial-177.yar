rule Win_Trojan_Trivial_177
{
strings:
	$a0 = { 2193ba0001b440b123cd21b43ecd21c32a2e432a00 }


condition:
	$a0
}