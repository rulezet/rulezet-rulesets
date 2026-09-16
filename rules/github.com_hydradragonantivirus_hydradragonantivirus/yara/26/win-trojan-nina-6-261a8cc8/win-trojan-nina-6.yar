rule Win_Trojan_Nina_6
{
strings:
	$a0 = { 8eda9cfac7068400ba028c0e8600 }


condition:
	$a0
}