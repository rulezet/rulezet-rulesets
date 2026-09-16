rule Win_Trojan_Tiny_97
{
strings:
	$a0 = { c38bd6ac3c2e75fb66c704636f6d20b45bcd2172eb93b440b233 }


condition:
	$a0
}