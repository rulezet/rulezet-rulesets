rule Win_Trojan_Zibbert_1
{
strings:
	$a0 = { cd2181fb34127403e9f803e93903505351521e0657 }


condition:
	$a0
}