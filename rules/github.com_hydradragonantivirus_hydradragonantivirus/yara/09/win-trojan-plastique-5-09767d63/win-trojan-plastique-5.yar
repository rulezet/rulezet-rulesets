rule Win_Trojan_Plastique_5
{
strings:
	$a0 = { 0681002e8c0685002e8c0689008cc005 }


condition:
	$a0
}