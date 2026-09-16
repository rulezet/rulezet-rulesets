rule Win_Trojan_Violetta_8
{
strings:
	$a0 = { cdffb431ba0011b104d3ea42cd219090 }


condition:
	$a0
}