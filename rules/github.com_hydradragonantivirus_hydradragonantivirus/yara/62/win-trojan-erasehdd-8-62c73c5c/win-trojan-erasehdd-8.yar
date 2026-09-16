rule Win_Trojan_EraseHDD_8
{
strings:
	$a0 = { 1e1eb800005053515206b403b001bb2201b500b101b600b2800e07cd13075a595bcb }


condition:
	$a0
}