rule Win_Trojan_Trivial_300
{
strings:
	$a0 = { b4a9b44e80c1d280e9d2ba2f01cd21b4e9b43cba9e00cd21b7c1 }


condition:
	$a0
}