rule Win_Trojan_Horror_4
{
strings:
	$a0 = { 83c70ab94e042e8a849d042e3005fec047e2f8c3 }


condition:
	$a0
}