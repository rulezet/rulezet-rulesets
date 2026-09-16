rule Win_Trojan_Dikshev_22
{
strings:
	$a0 = { 652ab99e00b44e87ceba0001cd217301c38bd6ac3c2e75fb5066c704636f6d20b45bcd215972e993b440eb }


condition:
	$a0
}