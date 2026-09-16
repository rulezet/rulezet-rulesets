rule Win_Trojan_AD_3
{
strings:
	$a0 = { 40b9ad0090555acd21b8004233c933d2cd215e568b441a }


condition:
	$a0
}