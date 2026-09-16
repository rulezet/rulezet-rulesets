rule Win_Trojan_School_2
{
strings:
	$a0 = { c08ec0b80102bb007a33d2b9015006532e803e157cf07405b280b91000cd13cbbb007cb80102 }


condition:
	$a0
}