rule Win_Trojan_Kilok_3
{
strings:
	$a0 = { 020055a60a000100ffff6a080000700d0000040000006a08 }


condition:
	$a0
}