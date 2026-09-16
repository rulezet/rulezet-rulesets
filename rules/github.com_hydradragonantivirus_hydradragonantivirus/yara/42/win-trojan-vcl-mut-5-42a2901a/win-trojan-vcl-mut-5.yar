rule Win_Trojan_VCL_MUT_5
{
strings:
	$a0 = { f6e595e85d01b9040051e8080059e2f9b8004ccd21558bec83ec40b44732d28d76c0cd21ba4201e81d00b43bba3f01 }


condition:
	$a0
}