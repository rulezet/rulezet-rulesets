rule Win_Trojan_Semtex_3
{
strings:
	$a0 = { 3e00005a7417408ec026813e0000cd20750526293e0200 }


condition:
	$a0
}