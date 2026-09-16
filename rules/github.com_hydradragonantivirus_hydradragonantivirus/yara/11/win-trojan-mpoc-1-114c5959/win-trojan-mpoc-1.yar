rule Win_Trojan_Mpoc_1
{
strings:
	$a0 = { 89969d063e89869b060e07b4408d960001b96f05cd21b8004233c999cd21b4408d96990659cd21 }


condition:
	$a0
}