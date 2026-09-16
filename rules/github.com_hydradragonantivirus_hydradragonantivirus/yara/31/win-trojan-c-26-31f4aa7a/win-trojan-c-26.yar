rule Win_Trojan_C_26
{
strings:
	$a0 = { 5d81ed11008bf581c60c008a148a64018bf581c635008bfeb9970890ac2ac402e2aae2f8 }


condition:
	$a0
}