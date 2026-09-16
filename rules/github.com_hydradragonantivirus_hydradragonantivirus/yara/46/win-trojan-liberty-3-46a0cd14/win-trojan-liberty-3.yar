rule Win_Trojan_Liberty_3
{
strings:
	$a0 = { 8ae00c80e66186e0e661b020b90900e620e2fcbb00b88ec3b904000e1f51c6062b040033c9 }


condition:
	$a0
}