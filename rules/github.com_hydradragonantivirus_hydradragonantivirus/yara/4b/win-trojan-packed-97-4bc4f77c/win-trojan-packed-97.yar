rule Win_Trojan_Packed_97
{
strings:
	$a0 = { 60e98d0500000d0ac4c4c4c4c4c4c4c4 }


condition:
	$a0
}