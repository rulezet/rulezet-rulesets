rule Win_Trojan_Spic_1
{
strings:
	$a0 = { f5e0b9a2b4b0b9b9b9b9b9b9b9b9b9b9b99920045b537069435d0420 }


condition:
	$a0
}