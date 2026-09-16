rule Win_Trojan_Pixel_31
{
strings:
	$a0 = { b90600b44ecd21726cbad602b8023d }


condition:
	$a0
}