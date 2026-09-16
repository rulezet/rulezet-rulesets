rule Win_Spyware_ye_85
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]52985ca96d14477113b8dbcdf592c2 }


condition:
	$a0
}