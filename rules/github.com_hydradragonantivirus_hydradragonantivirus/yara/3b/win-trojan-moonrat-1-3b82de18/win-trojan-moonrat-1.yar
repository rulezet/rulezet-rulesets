rule Win_Trojan_Moonrat_1
{
strings:
	$a0 = { b440cd8a5a1f8cc18cc2b80242cd8a1e33c08ed8ba0002b9f501b440cd8a1fe98aff80fc56 }


condition:
	$a0
}