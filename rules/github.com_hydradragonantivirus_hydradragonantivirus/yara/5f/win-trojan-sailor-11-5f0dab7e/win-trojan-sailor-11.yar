rule Win_Trojan_Sailor_11
{
strings:
	$a0 = { b418????cd213d50537502ffe3 }


condition:
	$a0
}