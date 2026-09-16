rule Win_Trojan_E_14
{
strings:
	$a0 = { 2e010691000e06068cc0488ec0268b1e030083eb1a07 }


condition:
	$a0
}