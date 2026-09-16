rule Win_Trojan_Dictator_1
{
strings:
	$a0 = { c075038b45088be88db505000000b998000000b866434100310683c6040540a78d4ce2f42bf581 }


condition:
	$a0
}