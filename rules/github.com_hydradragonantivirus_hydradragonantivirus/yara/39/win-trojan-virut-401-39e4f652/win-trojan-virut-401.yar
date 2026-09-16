rule Win_Trojan_Virut_401
{
strings:
	$a0 = { 90f6d0f6d08d36fce80700000008ff90 }


condition:
	$a0
}