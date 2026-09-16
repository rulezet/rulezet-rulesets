rule Win_Trojan_Vesna_1
{
strings:
	$a0 = { 5b83c30653c31e56e81800eac80000005e1f2e9c589e72f3eb2990585b83c3055350c31f31f61e8edebe04008c }


condition:
	$a0
}