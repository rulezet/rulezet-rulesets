rule Win_Spyware_ye_147
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]905e9a6fabcafdafd1fea10babc8f8 }


condition:
	$a0
}