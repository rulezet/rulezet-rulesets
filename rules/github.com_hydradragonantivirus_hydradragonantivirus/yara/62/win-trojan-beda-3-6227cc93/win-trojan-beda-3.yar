rule Win_Trojan_Beda_3
{
strings:
	$a0 = { 1e068cc82e0106c201b8dabecd213ddada7503e9a600b451cd214b8edb832e03002843031e03008edbc60600004dc7 }


condition:
	$a0
}