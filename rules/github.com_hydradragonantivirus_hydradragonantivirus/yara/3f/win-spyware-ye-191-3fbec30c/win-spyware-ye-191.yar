rule Win_Spyware_ye_191
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]bc02c613d7fea9d3fda2cd3f670c44 }


condition:
	$a0
}