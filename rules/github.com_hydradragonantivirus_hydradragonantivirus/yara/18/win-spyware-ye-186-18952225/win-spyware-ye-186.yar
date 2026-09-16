rule Win_Spyware_ye_186
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]b705c116d2f1a4d6f8a5c83252772f }


condition:
	$a0
}