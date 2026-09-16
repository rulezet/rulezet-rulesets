rule Win_Trojan_Alien_3
{
strings:
	$a0 = { cd21b43ecd215a8bda807f26007502eb061fb8000150c3b400cd13b80905b500ba8000cd13 }


condition:
	$a0
}