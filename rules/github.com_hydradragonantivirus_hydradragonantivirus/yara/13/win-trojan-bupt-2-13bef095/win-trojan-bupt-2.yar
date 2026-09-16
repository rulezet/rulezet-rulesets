rule Win_Trojan_Bupt_2
{
strings:
	$a0 = { 0102b90e00ba0001bb0006cd13c6061d7c00ea4d060000 }


condition:
	$a0
}