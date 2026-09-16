rule Win_Spyware_ye_167
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]a46aae7bbfe6913b650ab5274f742c }


condition:
	$a0
}