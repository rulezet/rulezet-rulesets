rule Win_Trojan_Poseidon_18
{
strings:
	$a0 = { 558bec83e4f881eca40a00008b450853a3d4dd420033c05666898424a4080000 }

	$a1 = { 53ff742424ff1504b24100eb0233c05f5e5b8be55dc21000 }


condition:
	$a0 and $a1
}