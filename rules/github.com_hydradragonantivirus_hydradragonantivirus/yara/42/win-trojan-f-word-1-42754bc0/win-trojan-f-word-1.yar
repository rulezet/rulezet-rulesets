rule Win_Trojan_F_word_1
{
strings:
	$a0 = { ba0000b000cd21b43fb9050080890201f2cd21d8fa8a1580fab9751d3ecd21f68bfe81 }


condition:
	$a0
}