rule Win_Trojan_N_61
{
strings:
	$a0 = { 8bf583ed0333ffbb7519b8ab1dcd2180fcab752284c0740fb93900bb0700acf6d0b40ecd10e2f7161f1607bf0001 }


condition:
	$a0
}