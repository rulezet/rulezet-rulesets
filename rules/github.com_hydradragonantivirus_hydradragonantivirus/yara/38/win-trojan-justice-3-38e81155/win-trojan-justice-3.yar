rule Win_Trojan_Justice_3
{
strings:
	$a0 = { eb592e89474d2e894f4eb8ff4bcd21 }


condition:
	$a0
}