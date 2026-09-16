rule Win_Trojan_Zeku_1
{
strings:
	$a0 = { 5768ff009a6f0a9b01bf94331e57bf41070e579a9d069b01bf94331e576a019ae106 }


condition:
	$a0
}