rule Win_Trojan_MiniMax_1
{
strings:
	$a0 = { a4ab268915bf9a018d31b164f3a433dbb801034132f6eb823c8050b80102ff7732730450cd1358 }


condition:
	$a0
}