rule Win_Spyware_Zbot_1286
{
strings:
	$a0 = { e8??0000005ec21800 }


condition:
	$a0
}