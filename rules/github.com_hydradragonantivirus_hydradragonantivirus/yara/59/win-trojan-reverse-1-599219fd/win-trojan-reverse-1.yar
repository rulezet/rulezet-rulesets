rule Win_Trojan_Reverse_1
{
strings:
	$a0 = { 06a403a3b203c706b0030000c706ae03cdabb8004233c933d2cd21720ab440b92000ba9c03cd21 }


condition:
	$a0
}