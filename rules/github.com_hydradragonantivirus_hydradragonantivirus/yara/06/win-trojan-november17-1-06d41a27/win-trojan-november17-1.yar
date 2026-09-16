rule Win_Trojan_November17_1
{
strings:
	$a0 = { ee05010e1f8b9c000183fb007410fa8dbc2501b9f103310d311d4743e2f8 }


condition:
	$a0
}