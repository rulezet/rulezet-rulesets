rule Win_Trojan_DualGtm_1
{
strings:
	$a0 = { bb4552b9415acd2181fb7447750981f9214d7503e99e028cc82d01005007268b1e03000e5803 }


condition:
	$a0
}