rule Win_Trojan_PCBB_7
{
strings:
	$a0 = { e800005b81c31000b9000033f680300046e2fa }


condition:
	$a0
}