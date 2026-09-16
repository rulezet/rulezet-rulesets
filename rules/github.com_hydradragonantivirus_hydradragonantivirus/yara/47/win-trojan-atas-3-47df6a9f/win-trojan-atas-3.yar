rule Win_Trojan_Atas_3
{
strings:
	$a0 = { b9df04be150001ee3004fec846e2f90341fdfd4546fdf9194ff3f40056450022cf6d100b9e8f50c6d328 }


condition:
	$a0
}