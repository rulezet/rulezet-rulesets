rule Win_Spyware_ye_78
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]4b9155a2660db8e28c315c4e761343 }


condition:
	$a0
}