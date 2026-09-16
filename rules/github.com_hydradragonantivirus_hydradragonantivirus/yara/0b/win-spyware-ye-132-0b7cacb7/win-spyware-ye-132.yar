rule Win_Spyware_ye_132
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]814f8b589c3b6e18bae78a7c244171 }


condition:
	$a0
}