rule Win_Trojan_Dust_2
{
strings:
	$a0 = { 01040055df00000100ffff0000000072010000060000000703 }


condition:
	$a0
}