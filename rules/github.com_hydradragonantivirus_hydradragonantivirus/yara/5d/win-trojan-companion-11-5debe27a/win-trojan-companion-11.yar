rule Win_Trojan_Companion_11
{
strings:
	$a0 = { 0200cd218bd8b440b9b500ba0001cd21b43ecd21c3 }


condition:
	$a0
}