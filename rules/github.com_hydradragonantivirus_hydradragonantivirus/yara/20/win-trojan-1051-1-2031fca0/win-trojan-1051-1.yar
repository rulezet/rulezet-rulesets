rule Win_Trojan_1051_1
{
strings:
	$a0 = { bb1301b90502ba00002e31172ed10f4343e2f6 }


condition:
	$a0
}