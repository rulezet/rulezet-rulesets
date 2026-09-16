rule Win_Trojan_Boot_22
{
strings:
	$a0 = { b80102bb000ab90100ba8000cd13be????bf????b9??00fcf3a4cd124848c1e0068ed83e813e0000eb0a74??2e803e000afa75??b80503bb0002b90100ba8000cd13cd20 }


condition:
	$a0
}