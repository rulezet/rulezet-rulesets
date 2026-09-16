rule Win_Trojan_Peed_285
{
strings:
	$a0 = { e8020000008f07c1e10283c40583ec017b0068fc7600005981c1305f000081c1fc760000ba?fa?bffff7d289d652ac86 }


condition:
	$a0
}