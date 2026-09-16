rule Win_Spyware_ye_129
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]7e4c885d99386315bfec9701a1c6fe }


condition:
	$a0
}