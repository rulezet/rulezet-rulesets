rule Win_Trojan_N_60
{
strings:
	$a0 = { 8bf583ed0333ffbb7519b8ab1dcd2180fcab752484c0740fb93c00bb0700acf6d0b40ecd10e2f7161f1607bf0001 }


condition:
	$a0
}