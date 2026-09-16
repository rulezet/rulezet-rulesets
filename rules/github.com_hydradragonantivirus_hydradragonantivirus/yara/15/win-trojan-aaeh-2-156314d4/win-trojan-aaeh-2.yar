rule Win_Trojan_AAEH_2
{
strings:
	$a0 = { 0000ebfdfcd6ead6d6d6d6d6e9eaeaecf5f5eae9d6d6d6d6d4cfd6c0d4d6ededeaf8ededfffcf5fff580d4f6f3a60000 }

	$a1 = { 7a7a7a7a7a757b7b787a7b726d73736d7179732e }


condition:
	$a0 and $a1
}