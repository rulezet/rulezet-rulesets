rule Win_Spyware_ye_13
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]0ad014e1254c7f294b7013852d4a7a }


condition:
	$a0
}