rule Win_Trojan_FichV_1
{
strings:
	$a0 = { ba3a0090b91c03be6b01bf6b01cceb0e }


condition:
	$a0
}