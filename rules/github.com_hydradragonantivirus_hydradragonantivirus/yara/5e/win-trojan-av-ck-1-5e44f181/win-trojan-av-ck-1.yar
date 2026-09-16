rule Win_Trojan_AV_CK_1
{
strings:
	$a0 = { b430cd213d031e750fe8ca017410b87461cd213d6174750681c4e601eb45b452cd21061fc47f120626c43d268b }


condition:
	$a0
}