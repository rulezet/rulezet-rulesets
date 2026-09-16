rule Win_Trojan_Sirius_29
{
strings:
	$a0 = { 582d0801958db62801e80200eb128b968c02b9b2008bfead33c2d1caabe2f8c3 }


condition:
	$a0
}