rule Win_Trojan_Lmir_109
{
strings:
	$a0 = { 0c0000006d697232686f6f6b2e646c6c00000000ffffffff040000005c2a }


condition:
	$a0
}