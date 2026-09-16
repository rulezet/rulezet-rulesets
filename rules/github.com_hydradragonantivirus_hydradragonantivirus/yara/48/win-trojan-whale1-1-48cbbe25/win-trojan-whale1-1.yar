rule Win_Trojan_Whale1_1
{
strings:
	$a0 = { 5bb985230e81eb9f231f8a47fffec830 }


condition:
	$a0
}