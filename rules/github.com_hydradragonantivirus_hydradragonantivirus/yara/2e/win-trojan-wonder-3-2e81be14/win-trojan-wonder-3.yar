rule Win_Trojan_Wonder_3
{
strings:
	$a0 = { 56b8001d50b8010050ff7604e82f0683c40856e8e5 }


condition:
	$a0
}