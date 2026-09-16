rule Win_Trojan_SkyNet_3
{
strings:
	$a0 = { 03b4408d960001b9a002cd21b8004233c933d2cd21b440b91c008d96ec03cd21b801573e }


condition:
	$a0
}