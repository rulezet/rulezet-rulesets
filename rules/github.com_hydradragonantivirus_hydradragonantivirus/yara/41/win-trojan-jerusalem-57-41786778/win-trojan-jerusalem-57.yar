rule Win_Trojan_Jerusalem_57
{
strings:
	$a0 = { 33dbbe????b94f072e8a47082e000046e2fb }


condition:
	$a0
}