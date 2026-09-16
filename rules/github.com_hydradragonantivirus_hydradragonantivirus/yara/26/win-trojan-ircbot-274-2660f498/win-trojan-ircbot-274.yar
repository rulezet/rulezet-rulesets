rule Win_Trojan_IRCBot_274
{
strings:
	$a0 = { d7d52e8c200cba643e397faee7ef18a4e913ceadb6c6e9586dc9dc54ec184a2714a539c366816df49a4e73c7193cbc9fd51f38e4df2c8cfeb605221fa2cb20f2b400b5004fb8fd5074a963bb9b94326a }


condition:
	$a0
}