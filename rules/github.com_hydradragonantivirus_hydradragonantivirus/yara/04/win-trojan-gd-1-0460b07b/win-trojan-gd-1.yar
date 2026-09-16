rule Win_Trojan_GD_1
{
strings:
	$a0 = { 028d0e1b0381e90001ba00019c2eff1eb302b43e8b1ebf029c2eff1eb3021f0761eb38906006 }


condition:
	$a0
}