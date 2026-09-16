rule Win_Trojan_VGEN_352
{
strings:
	$a0 = { cd213c02730533c00650cbbf5e098b3602002bf781fe00107203be0010fa8ed781c46e1afb7312161f0ee8570233 }


condition:
	$a0
}