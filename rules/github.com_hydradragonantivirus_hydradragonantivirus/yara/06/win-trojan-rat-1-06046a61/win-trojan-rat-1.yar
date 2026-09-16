rule Win_Trojan_Rat_1
{
strings:
	$a0 = { fcb82b35cd218cdd0e1f012e6a0abe10 }


condition:
	$a0
}