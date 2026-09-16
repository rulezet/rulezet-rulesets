rule Win_Trojan_Barrotes_3
{
strings:
	$a0 = { 01b440cd217303e948012e832e1b010333c933 }


condition:
	$a0
}