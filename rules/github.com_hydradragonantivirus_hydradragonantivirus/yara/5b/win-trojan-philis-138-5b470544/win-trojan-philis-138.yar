rule Win_Trojan_Philis_138
{
strings:
	$a0 = { 50565e893424548bf48b3683c404eb00 }


condition:
	$a0
}