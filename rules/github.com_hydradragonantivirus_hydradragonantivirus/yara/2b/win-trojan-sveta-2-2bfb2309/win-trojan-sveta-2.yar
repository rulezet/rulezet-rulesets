rule Win_Trojan_Sveta_2
{
strings:
	$a0 = { 020055df04000100ffff000000003e030000060000006a08 }


condition:
	$a0
}