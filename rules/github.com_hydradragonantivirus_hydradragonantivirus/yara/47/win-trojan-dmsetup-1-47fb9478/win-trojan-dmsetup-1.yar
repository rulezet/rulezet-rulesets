rule Win_Trojan_DMSetup_1
{
strings:
	$a0 = { cd213c02730533c00650cbbf1e068b3602002bf781fe00107203be0010fa8ed781c43e0efb7312161f0ee8570233 }


condition:
	$a0
}