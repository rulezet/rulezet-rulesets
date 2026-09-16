rule Win_Trojan_Lineage_480
{
strings:
	$a0 = { 833dc47640000075196a00a1507640005068c85140006a05e86feeffffa3c4764000c3 }


condition:
	$a0
}