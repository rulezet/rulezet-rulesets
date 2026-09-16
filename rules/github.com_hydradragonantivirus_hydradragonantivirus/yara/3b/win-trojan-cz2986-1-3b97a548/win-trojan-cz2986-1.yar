rule Win_Trojan_CZ2986_1
{
strings:
	$a0 = { 13eb3090bf6f09e83300aa3c6f90 }


condition:
	$a0
}