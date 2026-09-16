rule Win_Trojan_Tiny_89
{
strings:
	$a0 = { 01010055df010000000100000000001a000000060000004503 }


condition:
	$a0
}