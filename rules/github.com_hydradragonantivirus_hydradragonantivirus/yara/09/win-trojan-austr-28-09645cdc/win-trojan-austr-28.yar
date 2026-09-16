rule Win_Trojan_Austr_28
{
strings:
	$a0 = { 2c04ba0001cd21b8004233c933d2cd21b440b90400 }


condition:
	$a0
}