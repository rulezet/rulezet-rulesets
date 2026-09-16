rule Win_Trojan_FighterPOS_2
{
strings:
	$a0 = { 4d535220323030362043686970205265636f72646572 }

	$a1 = { 6d737232303036406f75746c6f6f6b2e636f6d2e6272 }


condition:
	$a0 and $a1
}