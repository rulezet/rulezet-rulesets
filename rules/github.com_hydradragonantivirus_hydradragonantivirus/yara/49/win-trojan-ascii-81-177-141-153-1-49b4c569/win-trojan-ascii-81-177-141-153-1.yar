rule Win_Trojan_Ascii_81_177_141_153_1
{
strings:
	$a0 = { 38312e3137372e3134312e313533 }


condition:
	$a0
}