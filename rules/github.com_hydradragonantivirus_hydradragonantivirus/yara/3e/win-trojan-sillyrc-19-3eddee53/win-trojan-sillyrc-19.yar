rule Win_Trojan_SillyRC_19
{
strings:
	$a0 = { e80c00598af2b280b80103cd13ebd0b42ccd218bda81c34892d1cbd1cbd1cba1af0048f7e342c3 }


condition:
	$a0
}