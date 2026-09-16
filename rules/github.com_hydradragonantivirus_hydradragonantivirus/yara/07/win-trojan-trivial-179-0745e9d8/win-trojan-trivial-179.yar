rule Win_Trojan_Trivial_179
{
strings:
	$a0 = { b44ecd21ba9e00b8013dcd2193b440b92300ba0001cd21b43ecd21c3 }


condition:
	$a0
}