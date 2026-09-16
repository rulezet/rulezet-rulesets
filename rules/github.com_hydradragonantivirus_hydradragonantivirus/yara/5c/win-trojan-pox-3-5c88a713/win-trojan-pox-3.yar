rule Win_Trojan_Pox_3
{
strings:
	$a0 = { 0190e800005d81ed06015053515256061e2ec6861e030033d28edaa10600488ed8b9ffff8bf28b0435f3a5740646e2f6 }


condition:
	$a0
}