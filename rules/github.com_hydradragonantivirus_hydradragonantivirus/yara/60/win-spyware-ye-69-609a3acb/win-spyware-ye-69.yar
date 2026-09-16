rule Win_Spyware_ye_69
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]42884c995d04b7e183284bbde58232 }


condition:
	$a0
}