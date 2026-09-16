rule Win_Trojan_Remor_1
{
strings:
	$a0 = { 04c60636050133ede96dfde81cffc60636050033edb43bba2505cd217203e954fd8b0e28058b }


condition:
	$a0
}