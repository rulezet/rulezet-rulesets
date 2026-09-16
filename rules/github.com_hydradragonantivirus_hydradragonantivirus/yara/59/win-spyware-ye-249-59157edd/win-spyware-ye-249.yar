rule Win_Spyware_ye_249
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]f6c400d511b0db8d37640ff9993e76 }


condition:
	$a0
}