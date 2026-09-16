rule Win_Trojan_Hooks_1
{
strings:
	$a0 = { faba0601b409cd21ebf7c3484f4f4b5320696e20796f752c20484f4f4b5320696e206d652c20484f4f4b532069 }


condition:
	$a0
}