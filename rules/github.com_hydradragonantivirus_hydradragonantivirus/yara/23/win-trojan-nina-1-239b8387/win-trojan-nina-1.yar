rule Win_Trojan_Nina_1
{
strings:
	$a0 = { f7b90001f3a4581ebd000155cb5858 }


condition:
	$a0
}