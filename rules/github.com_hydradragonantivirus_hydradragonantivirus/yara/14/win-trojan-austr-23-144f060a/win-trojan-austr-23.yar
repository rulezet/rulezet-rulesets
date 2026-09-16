rule Win_Trojan_Austr_23
{
strings:
	$a0 = { 40b97b02ba0001cd21b8004233c933d2cd21b440b90400 }


condition:
	$a0
}