rule Win_Trojan_Muhamor_1
{
strings:
	$a0 = { e48ff4e8106354befce48f0c32323c702afe322a0b34e4490c323243122acd32749010773401e46d }


condition:
	$a0
}