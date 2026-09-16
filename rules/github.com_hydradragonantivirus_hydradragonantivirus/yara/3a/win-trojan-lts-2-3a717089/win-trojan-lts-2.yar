rule Win_Trojan_LTS_2
{
strings:
	$a0 = { a3fc01b440b92901bae8fde87000b8004233c933d2 }


condition:
	$a0
}