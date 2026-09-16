rule Win_Trojan_Small_5405
{
strings:
	$a0 = { e8bbffffff85c0743c68341000106a016a }

	$a1 = { 646c6c0077696e31 }


condition:
	$a0 and $a1
}