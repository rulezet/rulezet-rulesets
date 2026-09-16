rule Win_Trojan_Beniev_1
{
strings:
	$a0 = { 68????????e86d0000008bc496ad83f8ff75f98b164a6633d266813a4d5a75f5 }


condition:
	$a0
}