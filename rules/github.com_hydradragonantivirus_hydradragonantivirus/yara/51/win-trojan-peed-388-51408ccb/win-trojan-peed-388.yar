rule Win_Trojan_Peed_388
{
strings:
	$a0 = { 89c28d9417a122000081c2e14e000081fae14e0000742e81fa63 }


condition:
	$a0
}