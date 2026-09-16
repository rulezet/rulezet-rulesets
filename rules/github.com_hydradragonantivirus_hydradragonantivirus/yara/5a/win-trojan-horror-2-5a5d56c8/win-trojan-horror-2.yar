rule Win_Trojan_Horror_2
{
strings:
	$a0 = { c70ab923042e8a846f042e3005fec047e2f8c3 }


condition:
	$a0
}