rule Win_Trojan_Ng_3
{
strings:
	$a0 = { cd283d6f00750d2e803e03014e7403e83103ebc3ba9503b104d3ea83c220c606d7020090e81c038c0e7a022ea1 }


condition:
	$a0
}