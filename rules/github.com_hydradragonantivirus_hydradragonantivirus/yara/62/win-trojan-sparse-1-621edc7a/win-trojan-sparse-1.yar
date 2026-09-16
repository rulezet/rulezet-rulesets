rule Win_Trojan_Sparse_1
{
strings:
	$a0 = { 17bb000106538cc64e8ede8c0601008cc6 }


condition:
	$a0
}