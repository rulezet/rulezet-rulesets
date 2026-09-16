rule Win_Trojan_VGEN_716
{
strings:
	$a0 = { 3583ec028975fec70500018b3dc3cd209090e90000c5ea80fc6c7406ea00000000b85053510652571e56e8ce00 }


condition:
	$a0
}