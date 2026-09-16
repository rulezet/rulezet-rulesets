rule Win_Trojan_Startpage_447
{
strings:
	$a0 = { 68746d6c2e70617a757a75 }

	$a1 = { 2e7265677772697465202671756f743b686b6c6d[0-48]5f70616765[0-167]796f75 }


condition:
	$a0 and $a1
}