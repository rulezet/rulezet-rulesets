rule Win_Trojan_Kilok_2
{
strings:
	$a0 = { 0500558d00000100ffffe20e00008f00000004000000e20e }


condition:
	$a0
}