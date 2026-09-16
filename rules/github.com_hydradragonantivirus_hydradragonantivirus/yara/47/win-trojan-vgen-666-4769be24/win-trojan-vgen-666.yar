rule Win_Trojan_VGEN_666
{
strings:
	$a0 = { e800005d81ed0901ba00feb41acd21e80000bf00018db61a02b90600f3a48d960e02b44e33c9cd21b8023dba1efecd21 }


condition:
	$a0
}