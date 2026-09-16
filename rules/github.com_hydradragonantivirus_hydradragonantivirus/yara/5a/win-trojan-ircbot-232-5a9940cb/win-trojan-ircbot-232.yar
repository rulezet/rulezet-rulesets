rule Win_Trojan_IRCBot_232
{
strings:
	$a0 = { 5f650152644564637476517368 }


condition:
	$a0
}