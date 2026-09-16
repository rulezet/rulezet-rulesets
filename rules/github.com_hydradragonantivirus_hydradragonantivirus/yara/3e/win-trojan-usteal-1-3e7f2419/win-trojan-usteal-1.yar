rule Win_Trojan_Usteal_1
{
strings:
	$a0 = { 6eb7b7ff4010400065d00000040200af240b010207331ce572b95c1601a1210e035332ffff6f772200f91704 }


condition:
	$a0
}