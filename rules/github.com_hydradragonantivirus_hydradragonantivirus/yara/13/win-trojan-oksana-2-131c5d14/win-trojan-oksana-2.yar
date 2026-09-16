rule Win_Trojan_Oksana_2
{
strings:
	$a0 = { f704bf19072bfe8bcf2e8a0434aa2e880446e2f5be0500 }


condition:
	$a0
}