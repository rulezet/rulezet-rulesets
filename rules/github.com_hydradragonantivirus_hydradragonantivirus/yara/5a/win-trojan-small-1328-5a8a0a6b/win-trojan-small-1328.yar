rule Win_Trojan_Small_1328
{
strings:
	$a0 = { 33ff897df4897df8897dfcffd66870d10010ff7510ff151ca1001085c05959740ac7057cdd001001000000 }


condition:
	$a0
}