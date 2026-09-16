rule Win_Trojan__0292_0001_002_1
{
strings:
	$a0 = { 2e2b0e1f01b4402e8b1e1d01ba4701cd21b4402e8b1e1d01b9cc01ba0001cd21b800422e8b }


condition:
	$a0
}