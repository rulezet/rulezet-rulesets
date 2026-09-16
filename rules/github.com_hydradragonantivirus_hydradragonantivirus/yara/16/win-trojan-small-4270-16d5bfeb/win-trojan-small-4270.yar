rule Win_Trojan_Small_4270
{
strings:
	$a0 = { 565805dc090000505f8d2d335adbfce8????????ba5a00000052[0-200]8b5c230066bb0000e9 }


condition:
	$a0
}