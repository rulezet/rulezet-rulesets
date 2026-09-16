rule Win_Trojan_Poseidon_15
{
strings:
	$a0 = { 558bec83e4f881ecb40a00008b450853a3b02e430033c0566689842444060000 }

	$a1 = { 53ff742414ff1540f24100eb0233c05f5e5b8be55dc21000 }


condition:
	$a0 and $a1
}