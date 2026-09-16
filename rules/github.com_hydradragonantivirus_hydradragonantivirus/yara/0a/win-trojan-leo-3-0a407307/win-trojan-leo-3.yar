rule Win_Trojan_Leo_3
{
strings:
	$a0 = { d2cd21722b0e1fb440b94c018bd583ea07cd21721bb8004233c933d2cd217210b440b90300ba11 }


condition:
	$a0
}