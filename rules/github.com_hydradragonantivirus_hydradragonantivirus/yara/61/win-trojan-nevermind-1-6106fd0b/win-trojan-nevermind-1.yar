rule Win_Trojan_NeverMind_1
{
strings:
	$a0 = { 8bf3bf3328b92303b2b48a0400053015464781fe }


condition:
	$a0
}