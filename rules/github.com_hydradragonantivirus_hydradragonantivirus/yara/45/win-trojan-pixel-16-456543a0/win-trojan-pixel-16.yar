rule Win_Trojan_Pixel_16
{
strings:
	$a0 = { c80500108ec0fe060401be000133 }


condition:
	$a0
}