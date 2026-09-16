rule Win_Trojan_Trivial_534
{
strings:
	$a0 = { b43ccd2193b44088e1ba0001cd21c3 }


condition:
	$a0
}