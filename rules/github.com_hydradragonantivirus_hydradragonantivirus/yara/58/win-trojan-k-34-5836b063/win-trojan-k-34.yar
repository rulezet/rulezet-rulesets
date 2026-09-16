rule Win_Trojan_K_34
{
strings:
	$a0 = { 0d012e8a8490032e8c84ad0350061e0e0e071fffb48c03ffb48e03ffb48803ffb48a03ffb49103ffb493038d94f403 }


condition:
	$a0
}