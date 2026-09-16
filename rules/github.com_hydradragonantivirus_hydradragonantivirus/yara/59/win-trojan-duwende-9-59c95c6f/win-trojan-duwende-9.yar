rule Win_Trojan_Duwende_9
{
strings:
	$a0 = { 03b440cd2159588b541acd218bceb440cd218b44188b4c168bd0241f80e1e00ac8b80157cd21 }


condition:
	$a0
}