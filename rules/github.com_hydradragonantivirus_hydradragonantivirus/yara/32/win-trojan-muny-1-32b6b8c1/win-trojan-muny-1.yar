rule Win_Trojan_Muny_1
{
strings:
	$a0 = { 9904c98335a88704c99d4ac99fccc03d8f65c18f39cd34a88d001b8d8c40acffd7dbeb063bfe88eb }


condition:
	$a0
}