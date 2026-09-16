rule Win_Trojan_Viperize_1
{
strings:
	$a0 = { 903c1f9074ea817c7900fa909077e1837c790a9072da }


condition:
	$a0
}