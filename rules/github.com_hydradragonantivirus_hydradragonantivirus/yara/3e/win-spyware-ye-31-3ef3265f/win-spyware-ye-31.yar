rule Win_Spyware_ye_31
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]1ce226f3375e09b3dd822d9fc7eca4 }


condition:
	$a0
}