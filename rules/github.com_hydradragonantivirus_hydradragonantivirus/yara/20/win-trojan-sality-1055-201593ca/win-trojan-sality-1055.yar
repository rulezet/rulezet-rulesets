rule Win_Trojan_Sality_1055
{
strings:
	$a0 = { 8a840516100000[0-6]fec2[0-6]3007[0-14]fec9 }


condition:
	$a0
}