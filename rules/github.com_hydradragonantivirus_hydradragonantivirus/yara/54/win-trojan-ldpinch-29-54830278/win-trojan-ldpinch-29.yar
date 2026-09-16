rule Win_Trojan_LdPinch_29
{
strings:
	$a0 = { 786e1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d726d78731d2c2f2a332d332d332c1d1d1d1d1d1d413733797c691d595c495c10171d }


condition:
	$a0
}