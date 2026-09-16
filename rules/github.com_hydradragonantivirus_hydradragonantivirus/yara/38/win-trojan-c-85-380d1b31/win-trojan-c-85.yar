rule Win_Trojan_C_85
{
strings:
	$a0 = { e800005d81ed0700508db61c008bfeb98402ac34 }


condition:
	$a0
}