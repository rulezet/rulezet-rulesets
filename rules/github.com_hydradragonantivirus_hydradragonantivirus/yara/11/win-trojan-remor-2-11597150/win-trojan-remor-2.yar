rule Win_Trojan_Remor_2
{
strings:
	$a0 = { 04c6063a050133ede96afde81cffc6063a050033edb43bba2905cd217203e951fd8b0e2c058b }


condition:
	$a0
}