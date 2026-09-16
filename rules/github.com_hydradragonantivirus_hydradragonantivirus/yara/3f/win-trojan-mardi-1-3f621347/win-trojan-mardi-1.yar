rule Win_Trojan_Mardi_1
{
strings:
	$a0 = { b89b0450cbb400cd13ba0000b93229 }


condition:
	$a0
}