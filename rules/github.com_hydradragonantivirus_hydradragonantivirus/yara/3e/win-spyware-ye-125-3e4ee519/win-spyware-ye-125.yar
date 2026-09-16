rule Win_Spyware_ye_125
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]7a408451953c6f19bbe083751dbaea }


condition:
	$a0
}