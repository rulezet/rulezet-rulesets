rule Win_Trojan_Cathin_1
{
strings:
	$a0 = { c36b80eb6b8d960001b90f03eb0190cd21b8004233d233c9cd21b492b4408d965404b91c00 }


condition:
	$a0
}