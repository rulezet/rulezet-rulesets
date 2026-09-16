rule Win_Spyware_ye_108
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]69b7734084235600a2cff2e48c2959 }


condition:
	$a0
}