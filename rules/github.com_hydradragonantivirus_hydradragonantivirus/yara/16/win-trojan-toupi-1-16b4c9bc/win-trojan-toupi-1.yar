rule Win_Trojan_Toupi_1
{
strings:
	$a0 = { 00006b6e6f77006b6e6f770000617373617373696e730000 }


condition:
	$a0
}