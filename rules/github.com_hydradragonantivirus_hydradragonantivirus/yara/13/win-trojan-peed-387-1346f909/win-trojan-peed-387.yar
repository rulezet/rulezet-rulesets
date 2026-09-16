rule Win_Trojan_Peed_387
{
strings:
	$a0 = { 89c28d9417a122000081ea1fb1ffff81fae14e00000f84aa00000081 }


condition:
	$a0
}