rule Win_Trojan_Trivial_98
{
strings:
	$a0 = { ba0e01cd21b43cba9e00cd212a2e2a00b74087ca93ebf3 }


condition:
	$a0
}