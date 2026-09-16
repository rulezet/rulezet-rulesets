rule Win_Trojan_YB_10
{
strings:
	$a0 = { e85c00e85900e85600e85300e800005e83ee2156fc81c67801bf0001a5a55ee83d00e83a00 }


condition:
	$a0
}