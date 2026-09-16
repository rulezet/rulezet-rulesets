rule Win_Trojan_12_1
{
strings:
	$a0 = { 8cc88ed0bc007c8bf48ec08ed850 }


condition:
	$a0
}