rule Win_Trojan_Idele_4
{
strings:
	$a0 = { b825000000b83b0800006a30680020400068092040006a00e8cf0b0000685220 }

	$a1 = { 6279204964656c65 }


condition:
	$a0 and $a1
}