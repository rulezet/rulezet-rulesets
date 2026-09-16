rule Win_Trojan_VGEN_635
{
strings:
	$a0 = { eb00e800005d81ed05015053515256061e2ec68618030033d28edaa10600488ed8b9ffff8bf28b0435f3a5740546e2f6 }


condition:
	$a0
}