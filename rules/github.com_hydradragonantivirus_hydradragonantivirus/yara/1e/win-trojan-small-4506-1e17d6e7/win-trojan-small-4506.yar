rule Win_Trojan_Small_4506
{
strings:
	$a0 = { e8??00000003018d760405????????89f78d7ffcc1c804abeb }


condition:
	$a0
}