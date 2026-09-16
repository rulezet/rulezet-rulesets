rule Win_Trojan_EVC_4
{
strings:
	$a0 = { 8bec8b6e0081ed030083c402bb1c018037004381fb370375f6 }


condition:
	$a0
}