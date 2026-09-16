rule Win_Trojan_Faggot_1
{
strings:
	$a0 = { c3b42ac606de030190e8d3ff3b0e }


condition:
	$a0
}