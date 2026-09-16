rule Win_Trojan_April30_1
{
strings:
	$a0 = { 01004e50e800005d81ed08018db61c0189f7b98b01ac0400aae2fa }


condition:
	$a0
}