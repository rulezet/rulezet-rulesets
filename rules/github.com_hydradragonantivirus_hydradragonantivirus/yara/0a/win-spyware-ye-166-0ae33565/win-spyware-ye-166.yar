rule Win_Spyware_ye_166
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]a369ad7abee5903a6409b4264e6b1b }


condition:
	$a0
}