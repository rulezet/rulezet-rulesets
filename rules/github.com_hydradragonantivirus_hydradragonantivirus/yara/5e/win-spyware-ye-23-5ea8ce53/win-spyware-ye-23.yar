rule Win_Spyware_ye_23
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]14da1eeb2f5601abd5faa517bfe49c }


condition:
	$a0
}