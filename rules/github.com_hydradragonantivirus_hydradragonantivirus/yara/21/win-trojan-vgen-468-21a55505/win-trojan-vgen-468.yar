rule Win_Trojan_VGEN_468
{
strings:
	$a0 = { 212e899e1e022e8c86200207b448bb0201cd217316068cc0488ec0268b1e030081eb040107 }


condition:
	$a0
}