rule Win_Spyware_ye_97
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]5eac68bd791843751f4c776101a6de }


condition:
	$a0
}