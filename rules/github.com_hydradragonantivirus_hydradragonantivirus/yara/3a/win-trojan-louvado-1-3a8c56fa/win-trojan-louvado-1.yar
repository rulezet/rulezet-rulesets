rule Win_Trojan_Louvado_1
{
strings:
	$a0 = { 01010055a605000000ffff3b0f0000c0070000060000003b0f }


condition:
	$a0
}