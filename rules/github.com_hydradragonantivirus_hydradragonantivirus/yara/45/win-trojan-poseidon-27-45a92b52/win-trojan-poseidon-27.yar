rule Win_Trojan_Poseidon_27
{
strings:
	$a0 = { 558bec81ece80c0000a15811440033c58945fc8b45088b4d14535657898580f7 }

	$a1 = { 8bb56cf7ffffffd6 }

	$a2 = { 8b4dfc5f5e33cd5be8f90000008be55dc21000 }


condition:
	$a0 and $a1 and $a2
}