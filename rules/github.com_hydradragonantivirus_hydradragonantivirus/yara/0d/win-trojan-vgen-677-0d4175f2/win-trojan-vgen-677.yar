rule Win_Trojan_VGEN_677
{
strings:
	$a0 = { 5d81ed0901ba00feb41acd21e80000bf00018db62b02b90600f3a48d961f02b44e33c9cd21e80000b8023dba1e }


condition:
	$a0
}