rule Win_Spyware_ye_58
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]3785419652712456782548b2d2f7af }


condition:
	$a0
}