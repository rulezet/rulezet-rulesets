rule Win_Spyware_Banker_2727
{
strings:
	$a0 = { 58c7a2b9cce796c3d886a0fb0aa0b179b02a8361e433ddec7f7fab45e825d9129314e1346b841b124e61b23aaa7fe045be3b4c67c0276e632a539ce0400b8cdc6bd81ede014d01d9c133aa4e35f9 }


condition:
	$a0
}