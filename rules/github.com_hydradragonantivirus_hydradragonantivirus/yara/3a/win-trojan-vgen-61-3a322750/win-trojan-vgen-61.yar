rule Win_Trojan_VGEN_61
{
strings:
	$a0 = { 5d81ed0b01bf00018db60501b90400fcf3a4b41a8d963302cd21c6865e0200b44e8db651028d962d0252eb3cb41a }


condition:
	$a0
}