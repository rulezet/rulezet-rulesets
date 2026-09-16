rule Win_Trojan_Tequila_2
{
strings:
	$a0 = { b96009[2-3]8a1489c730174643????81fe????7205 }


condition:
	$a0
}