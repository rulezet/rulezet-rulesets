rule Win_Trojan_Trojan_152
{
strings:
	$a0 = { b9a300ba00fdcd21b8004233c933d2cd21b440b9a300ba0001cd21b80157 }


condition:
	$a0
}