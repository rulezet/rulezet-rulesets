rule Win_Trojan_Zluk_1
{
strings:
	$a0 = { cd213df00f74534a8eda8b1e030081eb0001b44acd21b448bbff00cd2150488ed858a30100 }


condition:
	$a0
}