rule Win_Trojan_YouAreIll_1
{
strings:
	$a0 = { cd218cc0488ec083c30e268b078ec05026a000003c5a740958260306030040ebecb800aacd13 }


condition:
	$a0
}