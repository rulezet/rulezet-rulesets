rule Win_Spyware_ye_34
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]1fed29fe3a590cbee08d309a3a5f17 }


condition:
	$a0
}