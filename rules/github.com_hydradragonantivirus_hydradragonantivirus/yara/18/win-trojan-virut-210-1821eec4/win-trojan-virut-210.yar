rule Win_Trojan_Virut_210
{
strings:
	$a0 = { e813000000??8af2b9ea180000301002d640e2f9c30f31c3558b6c2404816c2404????0000e8eb }


condition:
	$a0
}