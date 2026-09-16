rule Win_Trojan_SlimLine_1
{
strings:
	$a0 = { 898606018986e901b440b1e58d960401cd2133c0e83500b440b1048d96e701cd21b801575a59 }


condition:
	$a0
}