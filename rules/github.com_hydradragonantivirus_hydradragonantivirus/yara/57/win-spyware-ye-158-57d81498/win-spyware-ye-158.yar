rule Win_Spyware_ye_158
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]9b61a572b6dd88325c01ac1e466313 }


condition:
	$a0
}