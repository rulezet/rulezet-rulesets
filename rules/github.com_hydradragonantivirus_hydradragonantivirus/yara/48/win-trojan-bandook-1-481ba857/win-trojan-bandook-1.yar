rule Win_Trojan_Bandook_1
{
strings:
	$a0 = { 25643a544350000025643a5443503a2a3a456e61626c65643a42616e646f6f6b00 }


condition:
	$a0
}