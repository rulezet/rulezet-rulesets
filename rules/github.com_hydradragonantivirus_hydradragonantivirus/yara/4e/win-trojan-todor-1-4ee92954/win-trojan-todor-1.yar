rule Win_Trojan_Todor_1
{
strings:
	$a0 = { 83c6208bfefcbab86aadd1ca33c2abe2f85ec3 }


condition:
	$a0
}