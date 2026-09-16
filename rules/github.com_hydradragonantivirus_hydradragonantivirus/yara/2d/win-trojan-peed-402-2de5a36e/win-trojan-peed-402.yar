rule Win_Trojan_Peed_402
{
strings:
	$a0 = { e806000000f7da291424c38d6424028d642402e83b0000005589e5ad83ee024e4ec9 }


condition:
	$a0
}