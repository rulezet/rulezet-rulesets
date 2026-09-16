rule Win_Spyware_ye_213
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]d218dc29ed94c7f193385b4d751242 }


condition:
	$a0
}