rule Win_Trojan_Nostardamus_9
{
strings:
	$a0 = { cd74043c7775f78d5406b8db25e895034ec704cdda5e56c39c262e80f43a80fc07744f80fc7974 }


condition:
	$a0
}