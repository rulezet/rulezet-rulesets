rule Win_Trojan_Pixel_19
{
strings:
	$a0 = { 0100012e8c1e02018bc32eff2e00 }


condition:
	$a0
}