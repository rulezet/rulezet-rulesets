rule Win_Trojan_Austr_25
{
strings:
	$a0 = { fa02ba0001cd21b8004233d233c9cd21b440b90400ba0001cd21595a }


condition:
	$a0
}