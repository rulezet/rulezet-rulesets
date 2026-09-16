rule Win_Trojan_Clonewar_9
{
strings:
	$a0 = { 2172538bd8b9f200ba0001b440cd21b43ecd21ba1a01b90300b80143cd21c3bcf2038bdc83c30f }


condition:
	$a0
}