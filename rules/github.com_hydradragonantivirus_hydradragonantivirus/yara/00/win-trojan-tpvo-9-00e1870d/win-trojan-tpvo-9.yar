rule Win_Trojan_TPVO_9
{
strings:
	$a0 = { cd213d83457578b42acd2181fa0d04753781c6c603 }


condition:
	$a0
}