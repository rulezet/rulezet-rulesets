rule Win_Trojan_Deicide_6
{
strings:
	$a0 = { 40ba0001b94b01cd21b457b0015a59cd21b43ecd218b1e }


condition:
	$a0
}