rule Win_Trojan_NoInt_3
{
strings:
	$a0 = { b90002161f33f68bfefcf3a436ff2e }


condition:
	$a0
}