rule Win_Trojan_Eocb_1
{
strings:
	$a0 = { e800005d81ed3f0180be4a0400742d80be4a0402741b061e0e0e1f078dbe1c048db62404b90400f3 }


condition:
	$a0
}