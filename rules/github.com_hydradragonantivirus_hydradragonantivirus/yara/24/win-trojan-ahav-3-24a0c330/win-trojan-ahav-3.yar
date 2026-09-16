rule Win_Trojan_Ahav_3
{
strings:
	$a0 = { 02b440b981018d960001cd21b8004233c933d2cd21 }


condition:
	$a0
}