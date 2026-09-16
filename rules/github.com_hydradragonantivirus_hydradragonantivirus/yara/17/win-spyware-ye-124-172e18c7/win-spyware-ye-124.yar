rule Win_Spyware_ye_124
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]7947835094336610b2df82741cb9e9 }


condition:
	$a0
}