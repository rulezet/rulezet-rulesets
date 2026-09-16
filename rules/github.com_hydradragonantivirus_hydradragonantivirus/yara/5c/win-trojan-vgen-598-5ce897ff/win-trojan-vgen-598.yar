rule Win_Trojan_VGEN_598
{
strings:
	$a0 = { c08ed0be007c8be6fb0e1fcd1248a31304b106d3e0b900028bd98ec033fffcf3a4b80102b601b90f000ad27905b9 }


condition:
	$a0
}