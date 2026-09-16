rule Win_Trojan_C99_13
{
strings:
	$a0 = { 47494638[0-70]3c68746d6c3e3c }

	$a1 = { 6339397368656c }


condition:
	$a0 and $a1
}