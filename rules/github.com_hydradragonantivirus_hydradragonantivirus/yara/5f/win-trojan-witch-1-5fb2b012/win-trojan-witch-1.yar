rule Win_Trojan_Witch_1
{
strings:
	$a0 = { b609eb8e4211917ca30559bdc89ed07463dfadeaa1491d02923fdae7fe05ea6d155bd6 }


condition:
	$a0
}