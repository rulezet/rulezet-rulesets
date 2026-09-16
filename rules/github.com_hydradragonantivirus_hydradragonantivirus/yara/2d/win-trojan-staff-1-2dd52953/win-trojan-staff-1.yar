rule Win_Trojan_Staff_1
{
strings:
	$a0 = { d333f6803800740343ebf8c600245a }


condition:
	$a0
}