rule Win_Trojan_WilVir_1
{
strings:
	$a0 = { 4033d2b900069cff1e6100b8024233c933d29cff1e6100b4408b0e6d0033d28e1e6b009c }


condition:
	$a0
}