rule Win_Trojan_Tracer_2
{
strings:
	$a0 = { b9fa02908d9604018b9e4403cd21b8004233c933d28b9e4403cd21b42ccd212e88968603b904 }


condition:
	$a0
}