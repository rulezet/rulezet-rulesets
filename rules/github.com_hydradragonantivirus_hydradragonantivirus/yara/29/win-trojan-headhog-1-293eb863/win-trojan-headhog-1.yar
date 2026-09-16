rule Win_Trojan_HeadHog_1
{
strings:
	$a0 = { 1ef902ba0301b92b02cdbb33c933d28b1ef902b800 }


condition:
	$a0
}