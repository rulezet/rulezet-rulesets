rule Win_Trojan_Amuck_1
{
strings:
	$a0 = { 067604000e1fb430bb4434cd2181fb4b4f7503e92c01b452cd21268b47fe33d28ed8803e00005a740703060300 }


condition:
	$a0
}