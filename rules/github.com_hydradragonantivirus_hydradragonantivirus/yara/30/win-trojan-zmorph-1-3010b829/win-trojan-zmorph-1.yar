rule Win_Trojan_ZMorph_1
{
strings:
	$a0 = { e8d954ffffe80a0000008b4b3c8b4c197803cbc381e30000ffff81c30000010081eb00000100803b4d0f849f54ffff }


condition:
	$a0
}