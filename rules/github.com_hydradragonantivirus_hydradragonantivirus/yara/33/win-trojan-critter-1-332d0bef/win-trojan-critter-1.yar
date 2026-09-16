rule Win_Trojan_Critter_1
{
strings:
	$a0 = { 341280fc30b4307420cd2181fa1234b80000740e8bd881 }


condition:
	$a0
}