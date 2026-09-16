rule Win_Trojan_GreenMonster_1
{
strings:
	$a0 = { c80558038ed8b9f90290bb260180378a434975f9 }


condition:
	$a0
}