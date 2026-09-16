rule Win_Trojan_Pixel_11
{
strings:
	$a0 = { 3fcd210513012ea30f01813e15015742 }


condition:
	$a0
}