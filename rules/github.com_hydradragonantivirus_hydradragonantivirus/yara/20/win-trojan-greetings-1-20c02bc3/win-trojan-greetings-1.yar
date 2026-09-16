rule Win_Trojan_Greetings_1
{
strings:
	$a0 = { 73014e8bfead33c3abe2fa5e595b58c3e8dbff8984f004b440 }


condition:
	$a0
}