rule Win_Trojan_Squad_1
{
strings:
	$a0 = { 50e800000e1f5b81eb0e01888719018dbf2601b9f2048035 }


condition:
	$a0
}