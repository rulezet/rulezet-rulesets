rule Win_Trojan_Packed_99
{
strings:
	$a0 = { e800000000a100904000ffe0 }


condition:
	$a0
}