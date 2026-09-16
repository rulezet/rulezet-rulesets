rule Win_Trojan_Komar_1
{
strings:
	$a0 = { 02b44233c933d2cd21b502c333d2b9b302b440cd213bc1c3b2204b4f4d415220b29cff1eb302cb }


condition:
	$a0
}