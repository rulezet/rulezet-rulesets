rule Win_Spyware_ye_244
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]f13ffbc80cabde882a577a6c14b1e1 }


condition:
	$a0
}