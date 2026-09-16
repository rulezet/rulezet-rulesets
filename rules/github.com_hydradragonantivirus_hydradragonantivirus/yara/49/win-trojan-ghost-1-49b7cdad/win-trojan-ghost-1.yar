rule Win_Trojan_Ghost_1
{
strings:
	$a0 = { b0002e8b1e3603b8004233d233c9e8defd2e8b1e3603b440b91800ba54032e8b1e3603e8c9fd2e }


condition:
	$a0
}