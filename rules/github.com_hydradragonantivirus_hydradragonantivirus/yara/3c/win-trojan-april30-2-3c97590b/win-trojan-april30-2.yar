rule Win_Trojan_April30_2
{
strings:
	$a0 = { e800005d81ed08018db61c018bfeb98b01ac0400aae2fa }


condition:
	$a0
}