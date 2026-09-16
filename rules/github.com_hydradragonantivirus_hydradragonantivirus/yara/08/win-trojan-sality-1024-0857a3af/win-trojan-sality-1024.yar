rule Win_Trojan_Sality_1024
{
strings:
	$a0 = { 60e84f000000908dbd0010400068[0-6]033c248bf7682f104000 }


condition:
	$a0
}