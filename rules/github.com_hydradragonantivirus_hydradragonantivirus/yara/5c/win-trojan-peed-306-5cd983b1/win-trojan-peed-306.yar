rule Win_Trojan_Peed_306
{
strings:
	$a0 = { e80200000087ec5eb9fe960100ba00002220c1ca0789d652ad05 }


condition:
	$a0
}