rule Win_Trojan_VGEN_379
{
strings:
	$a0 = { 5354455243554c4955535e83ee0356fc83c652bf0001a5a55e33c08ec0bfe00126817d035354741cb9f000f3a4 }


condition:
	$a0
}