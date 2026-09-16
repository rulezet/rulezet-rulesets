rule Win_Spyware_ye_101
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]62a86cb97d245701a3c8ebdd852252 }


condition:
	$a0
}