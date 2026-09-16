rule Win_Trojan_Ascii_122_224_35_9_1
{
strings:
	$a0 = { 3132322e3232342e33352e39 }


condition:
	$a0
}