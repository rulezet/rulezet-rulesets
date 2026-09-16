rule Win_Trojan_C99_14
{
strings:
	$a0 = { 47494638[0-70]3c68746d6c3e3c }

	$a1 = { 6339392076302e }


condition:
	$a0 and $a1
}