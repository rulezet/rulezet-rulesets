rule Win_Trojan_Small_4510
{
strings:
	$a0 = { b825120506352564450650e81f000000e8320000 }


condition:
	$a0
}