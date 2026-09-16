rule Win_Spyware_ye_46
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]2bf13582466d18426c11bc2e567323 }


condition:
	$a0
}