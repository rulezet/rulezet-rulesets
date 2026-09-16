rule Win_Trojan_BackOrifice_1
{
strings:
	$a0 = { 33ff85f67e238b4c241c03e933d28a142f5268d886410053e8b1d1000083c40c473bfe7ce78b6c24 }


condition:
	$a0
}