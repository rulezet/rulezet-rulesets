rule Win_Trojan_VGEN_671
{
strings:
	$a0 = { 5d81ed0901ba00feb41acd21e80000bf00018db62802b90600f3a48d961c02b44e33c9cd21b8023dba1efecd21 }


condition:
	$a0
}