rule Win_Trojan_V2100_3
{
strings:
	$a0 = { f7024f4f0ee8020047471eff7508cb }


condition:
	$a0
}