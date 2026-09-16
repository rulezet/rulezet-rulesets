rule Win_Trojan_Azusa_1
{
strings:
	$a0 = { b8ca0050cb31c0cd1331c08ec0b80102bb00 }


condition:
	$a0
}