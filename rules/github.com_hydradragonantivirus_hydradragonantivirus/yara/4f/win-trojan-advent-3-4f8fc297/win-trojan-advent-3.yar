rule Win_Trojan_Advent_3
{
strings:
	$a0 = { 140031044646e2f25e5958c3e8dfffcd }


condition:
	$a0
}