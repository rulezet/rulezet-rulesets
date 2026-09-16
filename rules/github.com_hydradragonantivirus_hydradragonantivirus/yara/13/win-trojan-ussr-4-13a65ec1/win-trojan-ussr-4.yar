rule Win_Trojan_USSR_4
{
strings:
	$a0 = { b92804b80040e84cfe3d2804751833c933d2b80042e83dfe }


condition:
	$a0
}