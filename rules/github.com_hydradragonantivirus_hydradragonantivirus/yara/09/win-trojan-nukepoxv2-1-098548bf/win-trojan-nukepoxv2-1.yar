rule Win_Trojan_NuKEPoXV2_1
{
strings:
	$a0 = { eb0190e800005d81ed060150535152565755061eb8cdabcd2181fbcdab74640e }


condition:
	$a0
}