rule Win_Trojan_VGEN_448
{
strings:
	$a0 = { fe063401e90a00268306130403fe0e3401b42fcd218cc0891e0b02a30d020e07e8ee008b160b02 }


condition:
	$a0
}