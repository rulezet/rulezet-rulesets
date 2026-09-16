rule Win_Trojan_Psycho_1
{
strings:
	$a0 = { 51b440b9d302ba0001cd21b43ecd219f }


condition:
	$a0
}