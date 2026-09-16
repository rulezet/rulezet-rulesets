rule Win_Spyware_ye_111
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]6cb27643872e5903add2fdef973c74 }


condition:
	$a0
}