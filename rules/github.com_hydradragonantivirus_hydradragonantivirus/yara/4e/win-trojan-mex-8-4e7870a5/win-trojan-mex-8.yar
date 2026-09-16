rule Win_Trojan_Mex_8
{
strings:
	$a0 = { 558bec81ecc40900005668a01040006a006a00ff15541040008985c4f6ffff83bdc4f6ffff00740d }


condition:
	$a0
}