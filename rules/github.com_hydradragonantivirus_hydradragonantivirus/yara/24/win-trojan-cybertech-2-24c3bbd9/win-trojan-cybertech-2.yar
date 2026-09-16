rule Win_Trojan_CyberTech_2
{
strings:
	$a0 = { e800005d81ed0600508db61b008bfeb91e04ac3400aae2fa }


condition:
	$a0
}