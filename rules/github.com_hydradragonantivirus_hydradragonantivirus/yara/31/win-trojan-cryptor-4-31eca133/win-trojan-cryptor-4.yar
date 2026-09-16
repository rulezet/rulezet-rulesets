rule Win_Trojan_Cryptor_4
{
strings:
	$a0 = { 0b00eb0eb44233c933d2cd21c3b440cd21c3b801572e8b8e900d2e8b96920dcd21b43e }


condition:
	$a0
}