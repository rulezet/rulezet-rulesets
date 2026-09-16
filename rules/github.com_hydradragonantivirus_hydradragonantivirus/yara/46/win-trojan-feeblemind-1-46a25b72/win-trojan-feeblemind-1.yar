rule Win_Trojan_Feeblemind_1
{
strings:
	$a0 = { 023d9c2eff1e030193b43080c410b9e500ba00010e1f9c2eff1e0301b43e9c2eff1e03015f }


condition:
	$a0
}