rule Win_Trojan_Youth_3
{
strings:
	$a0 = { baec04b9ec03e8c3fe72b73bc175b3b8004233c933d2e8b3feb440b9ec03ba0001e8a8fe8026 }


condition:
	$a0
}