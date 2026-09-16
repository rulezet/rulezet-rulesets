rule Win_Spyware_ye_214
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]d319dd2aee95c0ea943964567e1b4b }


condition:
	$a0
}