rule Win_Trojan_Kohn6_1
{
strings:
	$a0 = { 028b4c2c8b072bc189074343034c2e3bdf7ef1eb09 }


condition:
	$a0
}