rule Win_Trojan_Aos_1
{
strings:
	$a0 = { e800005d81ed????b863f6[0-2]cd2181f978d874408cc0[0-2]488ed8 }


condition:
	$a0
}