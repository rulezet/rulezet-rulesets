rule Win_Trojan_MG_2
{
strings:
	$a0 = { e8000050a10101050301962e8b84eb01a300012e8aa4ed0188260201b8044bcd217368 }


condition:
	$a0
}