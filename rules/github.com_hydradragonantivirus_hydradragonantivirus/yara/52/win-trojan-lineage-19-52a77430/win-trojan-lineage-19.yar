rule Win_Trojan_Lineage_19
{
strings:
	$a0 = { 494c4d4f4e2e45584500ffffffff0a0000004b41565046572e4558450000ffff }


condition:
	$a0
}