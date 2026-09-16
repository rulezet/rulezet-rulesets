rule Win_Trojan_SillyRC_35
{
strings:
	$a0 = { 53515256571e06558bec3d004b75731e078bfab95000 }


condition:
	$a0
}