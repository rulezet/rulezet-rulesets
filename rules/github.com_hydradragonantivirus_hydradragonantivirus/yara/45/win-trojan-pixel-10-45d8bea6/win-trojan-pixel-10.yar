rule Win_Trojan_Pixel_10
{
strings:
	$a0 = { 0652012eff2e5001b401b520cd10 }


condition:
	$a0
}