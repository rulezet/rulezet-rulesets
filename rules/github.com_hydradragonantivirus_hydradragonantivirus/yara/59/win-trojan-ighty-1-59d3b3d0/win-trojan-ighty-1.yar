rule Win_Trojan_Ighty_1
{
strings:
	$a0 = { 33c08ec026813e980177777503e9bc00b42acd2180fe0c750a80fa1f7505eb050000c80706bf00010ebe0001ba3b01 }


condition:
	$a0
}