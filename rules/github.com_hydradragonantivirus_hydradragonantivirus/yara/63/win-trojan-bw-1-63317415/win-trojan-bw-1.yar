rule Win_Trojan_BW_1
{
strings:
	$a0 = { 06e800005d81ed1c01e82c032e899e44042e8c8646040e1f8d962205b41ae809033ec6864c0400 }


condition:
	$a0
}