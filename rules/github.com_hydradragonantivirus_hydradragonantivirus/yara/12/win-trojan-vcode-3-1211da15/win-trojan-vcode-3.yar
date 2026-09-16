rule Win_Trojan_VCode_3
{
strings:
	$a0 = { 01018b3581c60301b8dcfecd2180fc13753a81c66e00bf00010e57b90300f3a4cbfc33f6b8dcfecd2180fc13751e }


condition:
	$a0
}