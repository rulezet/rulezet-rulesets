rule Win_Trojan_ZRK_1
{
strings:
	$a0 = { e800005e2e8a44f83c00740f83c61890 }


condition:
	$a0
}