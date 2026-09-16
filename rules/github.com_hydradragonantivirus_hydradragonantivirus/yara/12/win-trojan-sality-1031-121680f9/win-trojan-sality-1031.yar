rule Win_Trojan_Sality_1031
{
strings:
	$a0 = { 88841d16100000 }

	$a1 = { 8a841516100000 }


condition:
	$a0 and $a1
}