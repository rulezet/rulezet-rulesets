rule Win_Spyware_3449_1
{
strings:
	$a0 = { 6803800000e800007bf4909090680401000068b0b21413 }


condition:
	$a0
}