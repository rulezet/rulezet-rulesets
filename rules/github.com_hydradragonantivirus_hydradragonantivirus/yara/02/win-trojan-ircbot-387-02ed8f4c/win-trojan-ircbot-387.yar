rule Win_Trojan_IRCBot_387
{
strings:
	$a0 = { e8040000008fd2934445eb028a3160614d }


condition:
	$a0
}