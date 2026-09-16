rule Win_Trojan_URLspoof_2
{
strings:
	$a0 = { 20687265663d22 }

	$a1 = { 0125303040 }

	$a2 = { 223e }

	$a3 = { 3c2f }


condition:
	$a0 and $a1 and $a2 and $a3
}