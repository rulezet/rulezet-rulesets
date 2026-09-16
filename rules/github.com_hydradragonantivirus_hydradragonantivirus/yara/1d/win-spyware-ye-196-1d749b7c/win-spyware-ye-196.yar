rule Win_Spyware_ye_196
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]c10fcb18dcfbaed8faa7ca3c6401b1 }


condition:
	$a0
}