rule Win_Trojan_Poseidon_13
{
strings:
	$a0 = { 558bec81ec5c070000a17831430033c58945fc8b45085356576af433db50 }

	$a1 = { 8badc0f8ffffffd58b4dfc5f5e33cd5be8fc0000008be55dc21000 }


condition:
	$a0 and $a1
}