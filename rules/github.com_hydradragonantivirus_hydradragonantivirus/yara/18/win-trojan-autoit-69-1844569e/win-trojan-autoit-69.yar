rule Win_Trojan_Autoit_69
{
strings:
	$a0 = { 6266757363617465642e617533 }

	$a1 = { 234e6f5472617949636f6e0d0a676c6f62616c }


condition:
	$a0 and $a1
}