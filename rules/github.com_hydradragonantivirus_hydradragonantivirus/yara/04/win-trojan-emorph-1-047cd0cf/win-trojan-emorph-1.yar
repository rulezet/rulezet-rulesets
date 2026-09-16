rule Win_Trojan_Emorph_1
{
strings:
	$a0 = { ca7504b4ad9dcf3d004b74069d2eff2e0f0150535152 }


condition:
	$a0
}