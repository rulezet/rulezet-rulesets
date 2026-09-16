rule Win_Trojan_VGEN_739
{
strings:
	$a0 = { 0d012e8a848e032e8c84ab0350061e0e0e071fffb48a03ffb48c03ffb48603ffb48803ffb48f03ffb491038d94f203 }


condition:
	$a0
}