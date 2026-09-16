rule Win_Trojan_VGEN_249
{
strings:
	$a0 = { e800005d81ed0601e8df03a6592cec94ef2ab88e4ba012a003aa03abef9fc0e6ce785b31627d6fe6cec3692b07a8efa6 }


condition:
	$a0
}