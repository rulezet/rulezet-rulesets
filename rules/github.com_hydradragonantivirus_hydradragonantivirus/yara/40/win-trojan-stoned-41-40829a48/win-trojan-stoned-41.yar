rule Win_Trojan_Stoned_41
{
strings:
	$a0 = { 50cdd35872c6bfbe01bebe03b92100f3a54133db88360600cdd3cb }


condition:
	$a0
}