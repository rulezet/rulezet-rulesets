rule Win_Trojan_VGEN_689
{
strings:
	$a0 = { 81ed0901ba00feb41acd21e80000bf00018db61902b90600f3a48d960d02b44e33c9cd21b8023dba1efecd21898613 }


condition:
	$a0
}