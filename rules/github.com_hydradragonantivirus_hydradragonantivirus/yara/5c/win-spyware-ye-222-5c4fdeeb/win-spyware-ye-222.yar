rule Win_Spyware_ye_222
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]db21e532f69dc8f29cc1ecde862353 }


condition:
	$a0
}