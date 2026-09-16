rule Win_Spyware_ye_120
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]75bb7f5490376214bee38e7818bdf5 }


condition:
	$a0
}