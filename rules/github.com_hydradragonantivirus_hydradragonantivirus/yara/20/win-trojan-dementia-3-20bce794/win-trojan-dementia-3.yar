rule Win_Trojan_Dementia_3
{
strings:
	$a0 = { 5e81c66a108bfefdb92908bac33e0e0e1f07ad33c2 }


condition:
	$a0
}