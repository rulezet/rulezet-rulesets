rule Win_Trojan_Pixel_12
{
strings:
	$a0 = { be0e018bfefcac32c4aae2fa33ff8e062c0033c0b5 }


condition:
	$a0
}