rule Win_Trojan_Trivial_423
{
strings:
	$a0 = { cd21be1201b97e0080340046e2fae44084c07509ba7201b409cd21ebf1a20e013cf086e0be0001bf9001b912 }


condition:
	$a0
}