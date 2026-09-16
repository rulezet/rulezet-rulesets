rule Win_Trojan_Peed_407
{
strings:
	$a0 = { 89c28d9417a122000081ea1fb1ffff81fae14e00000f848200000081fa63d100 }


condition:
	$a0
}