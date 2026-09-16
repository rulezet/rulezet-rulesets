rule Win_Trojan_BitAddict_3
{
strings:
	$a0 = { d8b80040b9b00133d2cd21721bb8004233c933d2cd }


condition:
	$a0
}