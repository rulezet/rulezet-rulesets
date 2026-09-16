rule Win_Trojan_Assassin_2
{
strings:
	$a0 = { ff4545c43e8f07268b7b7ea4a575f21f5d58065053b82012cd2f268a1db81612cd2f5bffe5be }


condition:
	$a0
}