rule Win_Trojan_Ukraine_6
{
strings:
	$a0 = { e1935289511587ad40cfe75f48762867c9e7ba51524f012434b7e5ce002ae07fcd01f6b5695a42bb44 }


condition:
	$a0
}