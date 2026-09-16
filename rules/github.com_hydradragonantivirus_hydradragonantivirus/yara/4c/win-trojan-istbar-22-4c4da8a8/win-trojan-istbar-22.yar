rule Win_Trojan_Istbar_22
{
strings:
	$a0 = { 6163636f756e745f69643d687474703a2f2f77002e7329b06fdf407463682e1e6d2f3f006fd8b2d6 }


condition:
	$a0
}