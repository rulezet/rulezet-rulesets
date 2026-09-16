rule Win_Trojan_W_364
{
strings:
	$a0 = { 6681c1ef216681f50bee6681e1e75f5280cf3981c26e0000000fb6dd8bf181e573e3370dc3 }


condition:
	$a0
}