rule Win_Trojan_Tiny_25
{
strings:
	$a0 = { 01960e59f3a4ba5101b44ecd217301cbb8023d99b29ecd2193b43fba57015459cd21803e5701 }


condition:
	$a0
}