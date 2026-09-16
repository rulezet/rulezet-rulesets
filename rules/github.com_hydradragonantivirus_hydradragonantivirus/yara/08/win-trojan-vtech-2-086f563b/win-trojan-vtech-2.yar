rule Win_Trojan_VTech_2
{
strings:
	$a0 = { 2e8a04f6d8f6d02e88044681fe310b75efbf2f002e80354d4781ff310b740d2e80 }


condition:
	$a0
}