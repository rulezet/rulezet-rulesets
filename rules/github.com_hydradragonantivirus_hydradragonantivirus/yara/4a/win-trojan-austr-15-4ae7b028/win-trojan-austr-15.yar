rule Win_Trojan_Austr_15
{
strings:
	$a0 = { 40b97901ba0000cd21b8004233c933d2cd21b90300ba0000b440cd21 }


condition:
	$a0
}