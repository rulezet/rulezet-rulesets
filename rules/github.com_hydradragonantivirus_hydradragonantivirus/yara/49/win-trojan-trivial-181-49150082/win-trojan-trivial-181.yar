rule Win_Trojan_Trivial_181
{
strings:
	$a0 = { 1f01b44ecd21ba9e00b8013dcd2193b440b92400b123ba0001cd21cd21c3 }


condition:
	$a0
}