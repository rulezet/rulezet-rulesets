rule Win_Trojan_Necurs_65
{
strings:
	$a0 = { e82baa0000a1345044006a016890404400a304904400ffd0e8333d00 }


condition:
	$a0
}