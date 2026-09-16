rule Win_Trojan_Kylie_2
{
strings:
	$a0 = { b0cd2180fcb07412b4b1bf0001be }


condition:
	$a0
}