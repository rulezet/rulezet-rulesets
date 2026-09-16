rule Win_Spyware_ye_104
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]65ab6f4480275204aed3fee8882d65 }


condition:
	$a0
}