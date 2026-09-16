rule Win_Trojan_IRCBot_354
{
strings:
	$a0 = { 3a242e565dbc7ad3f6f84c5acc37522a6744e9e5d60a7ebb705f5cd65a7dbed61edad2d2f675566c5c261b7eb2164a8cd67e7f4a164abc68c77d8cd69e78058f33a1165d7c72b07e5b56d736d98e0433 }


condition:
	$a0
}