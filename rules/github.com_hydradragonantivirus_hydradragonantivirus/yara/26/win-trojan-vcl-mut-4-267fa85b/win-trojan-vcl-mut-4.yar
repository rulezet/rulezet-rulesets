rule Win_Trojan_VCL_MUT_4
{
strings:
	$a0 = { b9030051e8080059e2f9b8004ccd21558bec83ec40b44732d28d76c0cd21ba4701e82b00730fba4d01e82300 }


condition:
	$a0
}