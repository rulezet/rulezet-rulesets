rule Win_Spyware_ye_168
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]a56baf04c0e792c4ee933ea8c8eda5 }


condition:
	$a0
}