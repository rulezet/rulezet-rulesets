rule Win_Trojan_Small_184
{
strings:
	$a0 = { faaf60b025b3458ec0b13f9090f3a41f87013c2990907406ab8cc08701ab0e070e1f5f2bcef3a4ebd7608bf2ac3de940750b1e0e1f99b93f0090cd211f61eacd20 }


condition:
	$a0
}