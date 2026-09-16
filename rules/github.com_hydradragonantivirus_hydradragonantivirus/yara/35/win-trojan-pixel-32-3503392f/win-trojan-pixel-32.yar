rule Win_Trojan_Pixel_32
{
strings:
	$a0 = { 06000100012e8c1e02012eff2e0001 }


condition:
	$a0
}