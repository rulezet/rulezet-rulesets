rule Win_Trojan_Trivial_191
{
strings:
	$a0 = { b44eba1f01cd21b8023dba9e00cd2193ba0001b440b124cd21b43ecd21 }


condition:
	$a0
}