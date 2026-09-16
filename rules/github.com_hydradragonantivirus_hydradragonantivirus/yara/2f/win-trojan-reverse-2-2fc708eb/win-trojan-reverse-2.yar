rule Win_Trojan_Reverse_2
{
strings:
	$a0 = { b8cabacd213dbaab74528cd8488ed8 }


condition:
	$a0
}