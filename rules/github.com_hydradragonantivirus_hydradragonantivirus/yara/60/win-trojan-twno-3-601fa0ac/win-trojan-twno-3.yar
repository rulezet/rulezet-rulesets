rule Win_Trojan_TWNO_3
{
strings:
	$a0 = { 010100558e00000000ffff00000000b7020000080000008614 }


condition:
	$a0
}