rule Win_Trojan_VGEN_319
{
strings:
	$a0 = { 213c02730533c00650cbbf55098b3602002bf781fe00107203be0010fa8ed781c40e18fb7312161f0ee8570233 }


condition:
	$a0
}