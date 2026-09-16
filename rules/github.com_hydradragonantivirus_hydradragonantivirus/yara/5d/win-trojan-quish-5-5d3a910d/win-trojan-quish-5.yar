rule Win_Trojan_Quish_5
{
strings:
	$a0 = { e800005d81ed0701e82900eb4ce81c00b440b92e018d960001cd21fe862d01eb00e81000c3 }


condition:
	$a0
}