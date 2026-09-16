rule Win_Trojan_Packed_11
{
strings:
	$a0 = { 807c2408015690eb }


condition:
	$a0
}