rule Win_Trojan_Peed_109
{
strings:
	$a0 = { e80c0000005589e5ad83c6fd4ec9c2080029d287d15a8d1d14??400029d2528b }


condition:
	$a0
}