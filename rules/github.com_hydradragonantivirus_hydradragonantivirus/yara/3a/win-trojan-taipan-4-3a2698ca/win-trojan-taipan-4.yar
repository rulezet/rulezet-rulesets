rule Win_Trojan_TaiPan_4
{
strings:
	$a0 = { 740d3d004b7503e808002eff2eaf000e07cf505351 }


condition:
	$a0
}