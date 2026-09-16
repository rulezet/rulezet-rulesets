rule Win_Spyware_ye_126
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]7b418552963d6812bce18c7e264373 }


condition:
	$a0
}