rule Win_Trojan_PFS_2
{
strings:
	$a0 = { 4129952e9d2b992193a929902a29e43a2f91a62879e2 }


condition:
	$a0
}