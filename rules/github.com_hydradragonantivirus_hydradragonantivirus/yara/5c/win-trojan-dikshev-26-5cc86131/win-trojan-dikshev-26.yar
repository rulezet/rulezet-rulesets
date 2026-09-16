rule Win_Trojan_Dikshev_26
{
strings:
	$a0 = { 652abe9e0091b44eba0001cd2173039090c38bd6ac3c2e75fb66c704636f6d20b45bcd2172eb93b440b1319090 }


condition:
	$a0
}