rule Win_Spyware_ye_53
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]32f83c894d7427517318bb2d557222 }


condition:
	$a0
}