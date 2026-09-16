rule Win_Trojan_Spooky_15
{
strings:
	$a0 = { 7a02b4408d96cb00b94903cd21b8004233c933d2cd21b4408d967802b91c00cd21b007cd29 }


condition:
	$a0
}