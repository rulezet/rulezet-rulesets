rule Win_Trojan_Peed_234
{
strings:
	$a0 = { f8be7273030087fb733eff1584467807ff108f0573733400f7d3683736040055 }


condition:
	$a0
}