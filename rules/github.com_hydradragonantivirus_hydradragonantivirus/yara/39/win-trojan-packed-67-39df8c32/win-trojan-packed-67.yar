rule Win_Trojan_Packed_67
{
strings:
	$a0 = { e8f7feffff0575070000ffe0e8ebfeffff058f1a0000ffe0e804000000ffffffff5ec3 }


condition:
	$a0
}