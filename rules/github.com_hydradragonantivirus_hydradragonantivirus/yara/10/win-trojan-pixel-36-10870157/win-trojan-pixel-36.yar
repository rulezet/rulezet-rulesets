rule Win_Trojan_Pixel_36
{
strings:
	$a0 = { 0100012e8c1e02018bc32eff2e0001 }


condition:
	$a0
}