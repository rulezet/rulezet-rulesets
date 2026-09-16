rule Win_Trojan_VGEN_684
{
strings:
	$a0 = { e800005d81ed0901ba00feb41acd21e80000bf00018db63302b90600f3a48d962702b44e33c9cd21e80000b8023dba1e }


condition:
	$a0
}