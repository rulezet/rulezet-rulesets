rule Win_Trojan_Barrotes_9
{
strings:
	$a0 = { 10002e0144732e8e547333c02e834439102eff6c37534f }


condition:
	$a0
}