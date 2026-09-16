rule Win_Trojan_Tanko_1
{
strings:
	$a0 = { 02bb00028a0e3a0180f9097402fec6cd137303e9810033c08ec0be0004bf007cb90001fcf3a5 }


condition:
	$a0
}