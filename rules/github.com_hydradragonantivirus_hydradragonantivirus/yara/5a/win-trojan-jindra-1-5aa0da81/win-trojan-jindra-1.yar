rule Win_Trojan_Jindra_1
{
strings:
	$a0 = { bbd52190f8514f4a47fdb9fa004e4a4642f8f846fde8d6076b96ef234b7749234b3bb5b18ff6db5ec4614f4d74 }


condition:
	$a0
}