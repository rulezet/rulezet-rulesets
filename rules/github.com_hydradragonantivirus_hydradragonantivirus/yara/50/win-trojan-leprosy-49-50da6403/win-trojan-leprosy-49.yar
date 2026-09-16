rule Win_Trojan_Leprosy_49
{
strings:
	$a0 = { 0350e80f005bb9b203ba0001b440cd21e80100c3bb30 }


condition:
	$a0
}