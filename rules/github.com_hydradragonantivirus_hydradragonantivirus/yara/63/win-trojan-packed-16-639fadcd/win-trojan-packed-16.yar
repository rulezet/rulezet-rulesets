rule Win_Trojan_Packed_16
{
strings:
	$a0 = { 504858e9b7fbffff0000000000000000 }


condition:
	$a0
}