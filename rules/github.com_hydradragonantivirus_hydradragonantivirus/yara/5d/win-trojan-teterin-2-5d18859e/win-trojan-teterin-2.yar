rule Win_Trojan_Teterin_2
{
strings:
	$a0 = { 4e41f9668bca44050540cb495533ed0bd2790845f7d844a34cf78312bc3e790b450fd9512994f7 }


condition:
	$a0
}