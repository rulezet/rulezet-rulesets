rule Win_Trojan_Jumper_1
{
strings:
	$a0 = { b80300509a7701dc0089ec5dc3045041544855633a5c646f733b633a5c77696e3b633a5c }


condition:
	$a0
}