rule Win_Spyware_ye_42
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]27f53186426114466815b82242671f }


condition:
	$a0
}