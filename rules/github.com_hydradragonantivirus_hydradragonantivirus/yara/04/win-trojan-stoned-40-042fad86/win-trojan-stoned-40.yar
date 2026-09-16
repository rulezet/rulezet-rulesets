rule Win_Trojan_Stoned_40
{
strings:
	$a0 = { b403e8c200b81000e670eb0086e0e67186e0403c4072f1b80100cd1033d2bb0c00b92800b402 }


condition:
	$a0
}