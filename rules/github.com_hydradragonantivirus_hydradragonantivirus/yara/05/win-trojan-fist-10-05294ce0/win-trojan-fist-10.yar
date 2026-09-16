rule Win_Trojan_Fist_10
{
strings:
	$a0 = { 032acf5079cf59eca3aa9483aa87c45524b04da13f1f942461bddb4856576b845617a7cb593a5160404fc00931 }


condition:
	$a0
}