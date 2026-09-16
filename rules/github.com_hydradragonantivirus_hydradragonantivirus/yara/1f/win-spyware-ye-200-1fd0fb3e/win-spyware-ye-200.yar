rule Win_Spyware_ye_200
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]c50bcf24e08732640eb3dec8e88dc5 }


condition:
	$a0
}