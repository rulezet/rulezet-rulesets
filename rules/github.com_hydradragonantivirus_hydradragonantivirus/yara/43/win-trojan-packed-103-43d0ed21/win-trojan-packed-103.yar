rule Win_Trojan_Packed_103
{
strings:
	$a0 = { e3a7cecd80e7cecdc3c53772e3e1cecdfd45aed3986be7d2986ae7cdb86587ccb86487cfb86787cec3c52f32b86687c9 }


condition:
	$a0
}