rule Win_Trojan_Wb_1
{
strings:
	$a0 = { 01b43fb90100cd21803ef00187742a962d0200c6060001e9a30101b43ffec450ba0301b9ed00 }


condition:
	$a0
}