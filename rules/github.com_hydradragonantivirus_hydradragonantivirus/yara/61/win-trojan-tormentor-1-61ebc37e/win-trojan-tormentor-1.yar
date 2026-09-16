rule Win_Trojan_Tormentor_1
{
strings:
	$a0 = { 40b9d10189f2cd21721fb8004233c933d2cd21b440b90400bac90003d6cd217208b43ecd21b44f }


condition:
	$a0
}