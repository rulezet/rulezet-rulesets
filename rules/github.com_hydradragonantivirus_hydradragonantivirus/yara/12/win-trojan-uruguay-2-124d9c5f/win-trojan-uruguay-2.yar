rule Win_Trojan_Uruguay_2
{
strings:
	$a0 = { e800005b0e53b4028bf381c6440133c08ec0268a0e6c040ac9753ab402b275e4610c03e661b0b6e6438ac2e642ace6 }


condition:
	$a0
}