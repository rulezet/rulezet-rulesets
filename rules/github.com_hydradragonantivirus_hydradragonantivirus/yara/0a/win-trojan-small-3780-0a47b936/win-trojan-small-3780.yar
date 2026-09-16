rule Win_Trojan_Small_3780
{
strings:
	$a0 = { ffbcefe12bbc3b592e7c6df6f3077c3a9f5729d2b20e43d3b308778fb0947c5907067881bd00a2afe3d44cdaebdc6eeee8902665a351ac1b621ad5acd4da99daea572959adaba2dcd8852a15d202 }


condition:
	$a0
}