rule Win_Trojan_Assasin_7
{
strings:
	$a0 = { 26636f6e6e656374696f6e3d00000000ffffffff0b0000004173736173696e20322e3000ffffffff010000005f }


condition:
	$a0
}