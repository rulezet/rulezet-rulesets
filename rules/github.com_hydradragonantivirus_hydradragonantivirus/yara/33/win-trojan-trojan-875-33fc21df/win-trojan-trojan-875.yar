rule Win_Trojan_Trojan_875
{
strings:
	$a0 = { 3c3f706870 }

	$a1 = { 24627970746575 }

	$a2 = { 246175696d6d61[0-200]247665617a6c74[0-200]246d6261766868 }


condition:
	$a0 and $a1 and $a2
}