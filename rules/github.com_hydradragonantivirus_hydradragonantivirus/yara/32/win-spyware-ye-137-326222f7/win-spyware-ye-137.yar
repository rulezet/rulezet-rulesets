rule Win_Spyware_ye_137
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]86549065a1c0eb9dc7f49f09a9ce86 }


condition:
	$a0
}