rule Win_Trojan_Swizzor_511
{
strings:
	$a0 = { e8000000005a81c2cb510000ffe2 }


condition:
	$a0
}