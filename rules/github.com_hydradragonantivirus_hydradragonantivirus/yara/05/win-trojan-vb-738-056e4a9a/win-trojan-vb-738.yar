rule Win_Trojan_VB_738
{
strings:
	$a0 = { 2e006500780065 }

	$a1 = { 5c00520055004e005c[0-7]43003a005c00570049004e0044004f00570053005c }


condition:
	$a0 and $a1
}