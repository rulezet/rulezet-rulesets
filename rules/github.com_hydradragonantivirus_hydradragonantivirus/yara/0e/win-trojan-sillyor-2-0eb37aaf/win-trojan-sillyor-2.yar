rule Win_Trojan_SillyOR_2
{
strings:
	$a0 = { 80fc3e751e1e52515033c933d2b80042cdffb16d0e1f33d2b440cdff58cdff595a1fcfea }


condition:
	$a0
}