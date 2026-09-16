rule Win_Trojan_Autoit_109
{
strings:
	$a0 = { 6266757363617465642e617533 }

	$a1 = { 236e6f7472617969636f6e20676c6f62616c }


condition:
	$a0 and $a1
}