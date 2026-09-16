rule Win_Trojan_BAT_82
{
strings:
	$a0 = { 64656c20633a5c7374726970 }

	$a1 = { 64656c20633a5c6d616e692e6261743e3e }


condition:
	$a0 and $a1
}