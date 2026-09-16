rule Win_Trojan_Trivial_533
{
strings:
	$a0 = { cd2183????b43ccd2193b4405acd21c3 }


condition:
	$a0
}