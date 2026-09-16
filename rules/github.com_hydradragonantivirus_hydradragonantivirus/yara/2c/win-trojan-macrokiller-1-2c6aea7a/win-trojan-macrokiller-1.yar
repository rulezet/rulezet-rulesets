rule Win_Trojan_MacroKiller_1
{
strings:
	$a0 = { 0200558e00000000ffff6210000089010000080000006208 }


condition:
	$a0
}