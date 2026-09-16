rule Win_Spyware_ye_194
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]bf0dc91edaf9acde802d50badaffb7 }


condition:
	$a0
}