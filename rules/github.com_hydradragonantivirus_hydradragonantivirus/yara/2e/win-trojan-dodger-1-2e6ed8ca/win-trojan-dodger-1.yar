rule Win_Trojan_Dodger_1
{
strings:
	$a0 = { 0200558e00000200ffff1003000071010000030000000103 }


condition:
	$a0
}