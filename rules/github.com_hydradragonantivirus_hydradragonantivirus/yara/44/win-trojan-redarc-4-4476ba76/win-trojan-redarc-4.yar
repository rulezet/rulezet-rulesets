rule Win_Trojan_RedArc_4
{
strings:
	$a0 = { e80000975d83ed06bb0011b44acd217307071f610e56cbeab8d80203c5b104d3e8401e5b03c35007 }


condition:
	$a0
}