rule Win_Trojan_Cookie_2
{
strings:
	$a0 = { 3e1e57bf48201e57b8e01c50bf5a3f1e579a180bc000 }


condition:
	$a0
}