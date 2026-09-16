rule Win_Trojan_Zlob_2210
{
strings:
	$a0 = { 636f6465635f75726c3d22766964656f5f382e65786522 }

	$a1 = { 7372633d226d6574612e68746d6c22 }


condition:
	$a0 and $a1
}