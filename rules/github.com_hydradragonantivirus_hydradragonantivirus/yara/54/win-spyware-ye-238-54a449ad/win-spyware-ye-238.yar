rule Win_Spyware_ye_238
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]eb31f5c206add8822c517c6e16b3e3 }


condition:
	$a0
}