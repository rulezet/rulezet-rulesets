rule Win_Trojan_ErrorMem_1
{
strings:
	$a0 = { 053307890583c702e2f5c3e800005f8bdf81c71500b949 }


condition:
	$a0
}