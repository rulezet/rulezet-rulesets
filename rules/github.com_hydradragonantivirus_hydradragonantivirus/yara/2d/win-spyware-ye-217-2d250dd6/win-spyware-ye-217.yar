rule Win_Spyware_ye_217
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]d624e035f1903b6d17446f59791e56 }


condition:
	$a0
}