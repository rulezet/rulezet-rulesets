rule Win_Spyware_ye_107
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]68b6724783225507a9d6f9e3832050 }


condition:
	$a0
}