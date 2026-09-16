rule Win_Trojan_Wonder_2
{
strings:
	$a0 = { 56b8001d50b8010050ff7604e82f0683c40856 }


condition:
	$a0
}