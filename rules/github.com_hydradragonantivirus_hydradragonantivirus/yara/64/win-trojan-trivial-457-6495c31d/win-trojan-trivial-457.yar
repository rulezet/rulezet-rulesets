rule Win_Trojan_Trivial_457
{
strings:
	$a0 = { ba4a01cd21726bba9e00b8023dcd2193b43fb90300ba5001cd21803e50014b741b813e50014d5a7413b8 }


condition:
	$a0
}