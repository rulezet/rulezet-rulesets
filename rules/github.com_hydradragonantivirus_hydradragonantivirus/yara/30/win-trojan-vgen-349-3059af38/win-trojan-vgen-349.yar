rule Win_Trojan_VGEN_349
{
strings:
	$a0 = { c4e4403c7775fa86c4b4bbcd152d008505460050c359015057d1e6a11801fec48bf803fe8b05fec4965f58cf87 }


condition:
	$a0
}