rule Win_Trojan_Szamalk_4
{
strings:
	$a0 = { cd2181f9ca077303e9050180fe097303e9fd00b00250b980008b1642011ebb00008edbcd269d }


condition:
	$a0
}