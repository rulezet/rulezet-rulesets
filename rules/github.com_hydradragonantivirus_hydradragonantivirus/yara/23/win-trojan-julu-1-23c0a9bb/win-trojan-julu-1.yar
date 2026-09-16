rule Win_Trojan_Julu_1
{
strings:
	$a0 = { fd00741b8b850f2340008b1733d00501010101891783c704e2f0e8a2ffffffc3 }


condition:
	$a0
}