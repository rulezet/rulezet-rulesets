rule Win_Trojan_Fakecodecs_5
{
strings:
	$a0 = { 558bec83c4f0b894974600e81400567ca1b0 }


condition:
	$a0
}