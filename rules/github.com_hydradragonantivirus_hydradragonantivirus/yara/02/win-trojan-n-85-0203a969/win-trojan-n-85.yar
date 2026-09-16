rule Win_Trojan_N_85
{
strings:
	$a0 = { c64300e820dcfeffb8684f4300e83e67ffff33c05a595964891068434f43008d45fce8f9e3fcffc3e973e0fcffebf05f5e5b595dc3000000ffffffff0b0000005c6e756b653330 }


condition:
	$a0
}