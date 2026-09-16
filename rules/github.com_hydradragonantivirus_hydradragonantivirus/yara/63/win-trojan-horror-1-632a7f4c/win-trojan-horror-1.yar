rule Win_Trojan_Horror_1
{
strings:
	$a0 = { 83c70ab90a042e8a8456042e3005fec047e2f8c3 }


condition:
	$a0
}