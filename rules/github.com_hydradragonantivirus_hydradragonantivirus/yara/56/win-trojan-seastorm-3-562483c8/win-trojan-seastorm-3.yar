rule Win_Trojan_SeaStorm_3
{
strings:
	$a0 = { cd2000909050599090b801fa93909087d987cab9455987cb90909392cd16b9b101bb }


condition:
	$a0
}