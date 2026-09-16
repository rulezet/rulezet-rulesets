rule Win_Trojan_Gen_148
{
strings:
	$a0 = { 9a542608ff60a608f74042feb80a16cd2f3da82cbf5603504ebda717ac035c70d1dd05a0545eb0 }


condition:
	$a0
}