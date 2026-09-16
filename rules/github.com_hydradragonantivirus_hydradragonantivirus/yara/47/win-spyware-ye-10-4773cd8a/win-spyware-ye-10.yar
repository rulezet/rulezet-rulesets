rule Win_Spyware_ye_10
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]07d511e6224174264875188222477f }


condition:
	$a0
}