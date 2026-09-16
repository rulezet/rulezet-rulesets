rule Win_Spyware_ye_4
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]01cf0bd81cbbee983a670afca4c1f1 }


condition:
	$a0
}