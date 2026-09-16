rule Win_Spyware_ye_115
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]70be7a4f8b2a5d0fb1de816b0ba8d8 }


condition:
	$a0
}