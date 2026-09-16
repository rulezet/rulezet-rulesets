rule Win_Trojan_Swizzor_513
{
strings:
	$a0 = { e8000000005b81c3??b50800ffe3 }


condition:
	$a0
}