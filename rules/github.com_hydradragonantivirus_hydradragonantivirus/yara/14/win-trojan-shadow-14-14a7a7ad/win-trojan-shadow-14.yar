rule Win_Trojan_Shadow_14
{
strings:
	$a0 = { 180019001a001b001c001d001e001f004d6f6f6e536861646f77446c6c2e646c6c003f3f }


condition:
	$a0
}