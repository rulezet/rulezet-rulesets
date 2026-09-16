rule Win_Trojan_UNARJ_1
{
strings:
	$a0 = { e800005ef583ee09bb240003def52e8a944707f5b9f0062e3017f543e2f9 }


condition:
	$a0
}