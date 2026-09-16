rule Win_Spyware_ye_49
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]2efc388d496813456f1c47b1d1f6ae }


condition:
	$a0
}