rule Win_Trojan_Peed_199
{
strings:
	$a0 = { e8000000008d6424028d642402e84d0000005589e5ad83ee024e4ec9c20800f7 }


condition:
	$a0
}