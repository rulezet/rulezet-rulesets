rule Win_Trojan_Goblin_1
{
strings:
	$a0 = { bb0c00b9b206e800005e03de1e0e1f802f??43e2fa }


condition:
	$a0
}