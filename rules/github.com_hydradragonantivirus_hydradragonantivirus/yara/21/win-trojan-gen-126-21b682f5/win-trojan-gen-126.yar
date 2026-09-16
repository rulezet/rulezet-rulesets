rule Win_Trojan_Gen_126
{
strings:
	$a0 = { 06d4030174078ed0531e1eeb0550 }


condition:
	$a0
}