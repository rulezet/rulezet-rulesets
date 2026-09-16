rule Win_Trojan_Mex_7
{
strings:
	$a0 = { 558bec81ecc80900005668a01040006a006a00ff15541040008985c0f6ffff83bdc0f6ffff00740d }


condition:
	$a0
}