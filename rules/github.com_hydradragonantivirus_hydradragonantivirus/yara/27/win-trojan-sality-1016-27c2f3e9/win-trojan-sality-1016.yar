rule Win_Trojan_Sality_1016
{
strings:
	$a0 = { 60e859000000 }

	$a1 = { 6800280000598b2c2481ed06104000eb96 }


condition:
	$a0 and $a1
}