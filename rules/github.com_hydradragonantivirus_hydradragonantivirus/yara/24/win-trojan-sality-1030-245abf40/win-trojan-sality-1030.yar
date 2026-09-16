rule Win_Trojan_Sality_1030
{
strings:
	$a0 = { 8a841516100000 }

	$a1 = { 88841d16100000 }


condition:
	$a0 and $a1
}