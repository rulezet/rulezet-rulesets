rule Win_Trojan_Baba_470_1
{
strings:
	$a0 = { d8b44033d2b9d601cd2133c933d2b80042cd21b440bac2 }


condition:
	$a0
}