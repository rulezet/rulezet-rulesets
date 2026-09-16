rule Win_Trojan_Mango_2
{
strings:
	$a0 = { d601908d960001cd21b8004233c933d2cd21b440b9 }


condition:
	$a0
}