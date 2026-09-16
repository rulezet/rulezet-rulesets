rule Win_Trojan_C_86
{
strings:
	$a0 = { e800005d81ed0701508db61c0189f7b98402ac34 }


condition:
	$a0
}