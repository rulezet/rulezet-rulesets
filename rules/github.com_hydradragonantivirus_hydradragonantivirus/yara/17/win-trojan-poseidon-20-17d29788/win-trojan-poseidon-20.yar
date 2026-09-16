rule Win_Trojan_Poseidon_20
{
strings:
	$a0 = { 558bec81ec84080000a15480410033c58945fc8b45088b4d145356578d95f8fd }

	$a1 = { 8b8d98f7ffff390d88b041000f8e970000008b9dfcf7ffffffd35f5e5b8b4dfc33cde8050100008be55dc21000 }


condition:
	$a0 and $a1
}