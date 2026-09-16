rule Win_Trojan_EXEBUG_1
{
strings:
	$a0 = { cd2f2e8c1eb8018bcacd2f890eb60180f932740a8cc983c11051b8fd0050cbe86800b404cd1a }


condition:
	$a0
}