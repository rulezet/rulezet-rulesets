rule Win_Trojan_Austr_13
{
strings:
	$a0 = { 06ef01b8b440b95201ba0001cd21b8004233c933d2cd21b90300ba0001b440cd21 }


condition:
	$a0
}