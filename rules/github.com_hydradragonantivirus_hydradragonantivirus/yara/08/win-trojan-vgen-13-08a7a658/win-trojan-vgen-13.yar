rule Win_Trojan_VGEN_13
{
strings:
	$a0 = { 90e800005d81ed07018d9ed901ff374343ff37b41a8d96ef01cd21b801faba4559cd16b44e8d96cf01cd217275 }


condition:
	$a0
}