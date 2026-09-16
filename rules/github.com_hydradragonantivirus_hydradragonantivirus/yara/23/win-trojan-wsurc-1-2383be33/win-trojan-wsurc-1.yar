rule Win_Trojan_Wsurc_1
{
strings:
	$a0 = { 1ec0072e8b841e0133c333c62e89841e0183c60281fea10672e9 }


condition:
	$a0
}