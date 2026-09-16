rule Win_Trojan_VGEN_318
{
strings:
	$a0 = { 30cd213c02730533c00650cbbf59098b3602002bf781fe00107203be0010fa8ed781c45e1afb7312161f0ee8570233 }


condition:
	$a0
}