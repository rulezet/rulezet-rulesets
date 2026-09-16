rule Win_Spyware_ye_130
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]7f4d895e9a396c1e406d10fa9a3f77 }


condition:
	$a0
}