rule Win_Trojan_Deicide_7
{
strings:
	$a0 = { 40ba0001b95302cd21b457b0015a59cd21b43ecd218b1e }


condition:
	$a0
}