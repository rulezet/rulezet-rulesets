rule Win_Trojan_VCode_4
{
strings:
	$a0 = { 01018b3581c60301b8dcfecd2180fc19753a81c66d00bf00010e57b90300f3a4cbfc33f6b8dcfecd2180fc19751e }


condition:
	$a0
}