rule Win_Trojan_CFFL_1
{
strings:
	$a0 = { 4a8bec8b46fa2d02008b1e120681fbcdab74072d00018be8eb03bd00001e068cc88ed883fd007503e9d409b41a8d96 }


condition:
	$a0
}