rule Win_Trojan_Pixel_4
{
strings:
	$a0 = { b44fba9102cd217202eb98ba8000eb05 }


condition:
	$a0
}