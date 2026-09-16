rule Win_Trojan_Grog_23
{
strings:
	$a0 = { 16908bf48b34b919030e1f800474802c7de201c3 }


condition:
	$a0
}