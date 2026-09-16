rule Win_Spyware_ye_245
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]f238fcc90db4e79133587b6d15b2e2 }


condition:
	$a0
}