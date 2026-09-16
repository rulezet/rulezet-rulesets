rule Win_Trojan_ExeBug_5
{
strings:
	$a0 = { fafec8ab83c70434c0abb10bf3aab113b703e88cffb413cd2f2e8c1eb9008bcacd2f890eb7 }


condition:
	$a0
}