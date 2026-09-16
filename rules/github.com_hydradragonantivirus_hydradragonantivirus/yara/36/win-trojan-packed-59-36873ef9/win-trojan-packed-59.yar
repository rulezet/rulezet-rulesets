rule Win_Trojan_Packed_59
{
strings:
	$a0 = { e1c8cedfd4d3d893cec4ce000000000000000000ac0faccc2d8dac00e6045d4f2f4f4f4fcf4f4f4fb0b04f4f584f4f4f4f4f4f4f474f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f }


condition:
	$a0
}