rule Win_Trojan_Dikshev_20
{
strings:
	$a0 = { 2e652abe9e0091b44eba0001cd217301c38bd6ac3c2e75fb66c704636f6d20b45bcd2172eb93b440b12deb }


condition:
	$a0
}