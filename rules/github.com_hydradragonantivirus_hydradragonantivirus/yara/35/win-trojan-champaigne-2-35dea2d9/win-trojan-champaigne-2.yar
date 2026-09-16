rule Win_Trojan_Champaigne_2
{
strings:
	$a0 = { 8be933c981ed0701e89602e93e9035639ccb6f5e2ad5a22717639cdb6d5e285c615efc29156114291ee2145c99ebf2 }


condition:
	$a0
}