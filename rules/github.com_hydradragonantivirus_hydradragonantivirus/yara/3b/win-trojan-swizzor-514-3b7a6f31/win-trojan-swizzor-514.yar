rule Win_Trojan_Swizzor_514
{
strings:
	$a0 = { e800000000bb??b508005803c3ffe0 }


condition:
	$a0
}