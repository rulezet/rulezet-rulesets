rule Win_Trojan_Fair_2
{
strings:
	$a0 = { 0300eb1a902e8f06f606fa2e8c1611072e892613078cc88ed0bcf606fbc3 }


condition:
	$a0
}