rule Win_Spyware_ye_40
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]25eb2f84406712446e13be28486d25 }


condition:
	$a0
}