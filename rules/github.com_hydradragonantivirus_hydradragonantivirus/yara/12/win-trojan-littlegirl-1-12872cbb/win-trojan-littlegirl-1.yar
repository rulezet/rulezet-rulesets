rule Win_Trojan_LittleGirl_1
{
strings:
	$a0 = { cd213dcdab74511ea12c00508cd8488ed8832e03 }


condition:
	$a0
}