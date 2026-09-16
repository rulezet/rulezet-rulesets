rule Win_Trojan_VCL_30
{
strings:
	$a0 = { 3501b40eac0ac07404cd10ebf7be480133d2e80e00be4801ba0100e80500b8004ccd21b84300cd }


condition:
	$a0
}