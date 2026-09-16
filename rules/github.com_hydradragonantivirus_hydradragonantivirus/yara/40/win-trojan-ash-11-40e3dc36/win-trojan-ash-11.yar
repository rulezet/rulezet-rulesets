rule Win_Trojan_Ash_11
{
strings:
	$a0 = { 04008d96fb01cd21b8024233c933d2cd21b4408b0e3c02ba0401cd21b801438b8e2f02cd21 }


condition:
	$a0
}