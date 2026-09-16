rule Win_Trojan_Pixel_13
{
strings:
	$a0 = { b9ffffb43fcd2105e4022ea31201 }


condition:
	$a0
}