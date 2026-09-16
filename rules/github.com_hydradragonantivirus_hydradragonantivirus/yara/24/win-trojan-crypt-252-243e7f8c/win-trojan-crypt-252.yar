rule Win_Trojan_Crypt_252
{
strings:
	$a0 = { 558bec83c4f053b8c8734500e853eefaff8b1d7c9045006aec8b038b403050e8 }


condition:
	$a0
}