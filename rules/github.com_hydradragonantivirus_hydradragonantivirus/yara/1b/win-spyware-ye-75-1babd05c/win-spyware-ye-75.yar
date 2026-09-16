rule Win_Spyware_ye_75
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]489652a76302b5e7893659436300b0 }


condition:
	$a0
}