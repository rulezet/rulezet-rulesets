rule Win_Trojan_VGEN_463
{
strings:
	$a0 = { b44abbffffcd21b44a2bddcd214db4488bddcd211f5bc353b449cd215bc3b42ccd2181e10f0f }


condition:
	$a0
}