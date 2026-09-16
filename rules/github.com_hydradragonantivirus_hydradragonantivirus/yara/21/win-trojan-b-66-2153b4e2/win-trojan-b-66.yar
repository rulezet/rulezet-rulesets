rule Win_Trojan_B_66
{
strings:
	$a0 = { 8ed0bc007c1607b80102bb007eb90f4fba0001cd13ffe3 }


condition:
	$a0
}