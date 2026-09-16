rule Win_Trojan_Winlock_1
{
strings:
	$a0 = { 558bec83c4f0b828f14500e8a06bfaffa1dc1046008b00e8a075ffff8b0dd811 }


condition:
	$a0
}