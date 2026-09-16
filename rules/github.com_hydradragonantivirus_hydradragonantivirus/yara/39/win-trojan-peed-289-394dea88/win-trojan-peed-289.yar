rule Win_Trojan_Peed_289
{
strings:
	$a0 = { e8020000008f07c1e10283c40583ec017b0068fc7600005981c1305f000081c1 }


condition:
	$a0
}