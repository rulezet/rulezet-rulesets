rule Win_Trojan_Poseidon_12
{
strings:
	$a0 = { 558bec81ecf0060000a15881430033c58945fc8b45085356576af433ff50 }

	$a1 = { 8bad2cf9ffffffd58b4dfc5f5e33cd5be80b0100 }


condition:
	$a0 and $a1
}