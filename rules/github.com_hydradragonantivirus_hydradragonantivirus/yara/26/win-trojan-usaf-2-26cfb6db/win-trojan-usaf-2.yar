rule Win_Trojan_Usaf_2
{
strings:
	$a0 = { c686a603e889bea903b800425a59cd21b440b909008d96a603cd218bce83e903898ea103 }


condition:
	$a0
}