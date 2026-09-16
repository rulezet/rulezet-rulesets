rule Win_Trojan_Ahav_1
{
strings:
	$a0 = { 863b02b440b951018d960001cd21b8004233c933d2cd21 }


condition:
	$a0
}