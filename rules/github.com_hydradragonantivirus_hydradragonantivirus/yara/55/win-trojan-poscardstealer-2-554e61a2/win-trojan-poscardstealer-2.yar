rule Win_Trojan_POSCardStealer_2
{
strings:
	$a0 = { e8df650000e978feffffcccccccccccccccccccccc558bec57 }


condition:
	$a0
}