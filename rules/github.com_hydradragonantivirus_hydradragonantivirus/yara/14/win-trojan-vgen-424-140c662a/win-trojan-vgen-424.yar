rule Win_Trojan_VGEN_424
{
strings:
	$a0 = { 5d81ed0901ba00feb41acd21bf00013e8db62002b90600f3a48d961402b44e33c9cd21b8023dba1efecd218986 }


condition:
	$a0
}