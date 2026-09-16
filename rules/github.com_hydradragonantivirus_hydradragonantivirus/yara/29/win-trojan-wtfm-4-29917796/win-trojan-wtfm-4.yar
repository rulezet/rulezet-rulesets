rule Win_Trojan_Wtfm_4
{
strings:
	$a0 = { c35f32e480cc5732254757ebf1be224681ee8845b90e8381e9e681390c7239b851100511da39 }


condition:
	$a0
}