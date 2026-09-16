rule Win_Trojan_SkyNet_1
{
strings:
	$a0 = { 86c7038996c503b4408d960001b97702cd21b8004233c933d2cd21b440b91c008d96c303cd21b8 }


condition:
	$a0
}