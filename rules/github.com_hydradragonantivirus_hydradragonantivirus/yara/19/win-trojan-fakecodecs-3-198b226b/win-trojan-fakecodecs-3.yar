rule Win_Trojan_Fakecodecs_3
{
strings:
	$a0 = { 558bec6aff6850d340006800c7400064a100000000506489250000000083 }


condition:
	$a0
}