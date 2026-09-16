rule Win_Trojan_Overdoze_3
{
strings:
	$a0 = { 0201e80000e80d008b360001bcfeff81ee0901eb08b8050333dbcd16c38beeb86666cd2181fb6666745a0e1fb44abbffffcd2183eb1fb44acd21b448bb1e00 }


condition:
	$a0
}