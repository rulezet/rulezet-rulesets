rule Win_Trojan_BackFont_1
{
strings:
	$a0 = { 26807c013a7506268a1480ea40b436e8deff3dffff74 }


condition:
	$a0
}