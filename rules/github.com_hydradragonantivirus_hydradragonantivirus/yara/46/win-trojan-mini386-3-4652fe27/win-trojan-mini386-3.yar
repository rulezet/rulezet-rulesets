rule Win_Trojan_Mini386_3
{
strings:
	$a0 = { c933d2cd212d030097b4408bd5b97d0090cd21b8004233c933d2cd21fdc604e9897c01fc87d6b9 }


condition:
	$a0
}