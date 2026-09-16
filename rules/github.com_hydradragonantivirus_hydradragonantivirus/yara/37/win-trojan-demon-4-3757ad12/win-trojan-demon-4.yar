rule Win_Trojan_Demon_4
{
strings:
	$a0 = { e80000582d0301b104d3e88ccb03c38ed88a263b022e88260001b42acd2180fa1f7502ebf5b41aba5c02cd21ba2102b4 }


condition:
	$a0
}