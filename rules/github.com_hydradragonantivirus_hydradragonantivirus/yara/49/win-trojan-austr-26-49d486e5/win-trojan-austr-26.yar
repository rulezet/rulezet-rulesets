rule Win_Trojan_Austr_26
{
strings:
	$a0 = { 01b8b440b91003ba0001cd21b8004233c933d2cd21b90300ba0001b440cd21 }


condition:
	$a0
}