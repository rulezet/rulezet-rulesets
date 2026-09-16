rule Win_Trojan_Pixel_5
{
strings:
	$a0 = { 8cc80500108ed8b41aba18f9cd21b44e1eb1200e1fba7201cd211fba36f9723bb8023dcd219399b43fb9ffffcd21 }


condition:
	$a0
}