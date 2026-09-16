rule Win_Trojan_Leech_4
{
strings:
	$a0 = { 81c4e4038cd18cc88ed05b4c4c83c622 }


condition:
	$a0
}