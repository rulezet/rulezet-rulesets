rule Win_Trojan_Payback_2
{
strings:
	$a0 = { e70929c03c00772d2ddc676ab8c6613df460794da754e7cddda707faf994b61ba4472e48a88e2a91 }


condition:
	$a0
}