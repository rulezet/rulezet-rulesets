rule Win_Trojan_MtE_1
{
strings:
	$a0 = { d3ea83ea108cd903caba6d015152cbfcbf000106 }


condition:
	$a0
}