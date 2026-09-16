rule Win_Trojan_Unkempt_1
{
strings:
	$a0 = { 0300a34206b8004233c98bd1cd21b440b90300ba4106cd21b43ecd21c3b43fba4806b90200cd21 }


condition:
	$a0
}