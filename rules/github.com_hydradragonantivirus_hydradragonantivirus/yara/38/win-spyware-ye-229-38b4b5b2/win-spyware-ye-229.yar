rule Win_Spyware_ye_229
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]e228ec39fda4d78123486b5d05a2d2 }


condition:
	$a0
}