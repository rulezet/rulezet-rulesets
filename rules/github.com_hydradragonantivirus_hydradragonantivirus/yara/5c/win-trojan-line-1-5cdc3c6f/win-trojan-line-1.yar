rule Win_Trojan_Line_1
{
strings:
	$a0 = { 40ba0001b98c03cd217215b8004233c933d2cd21720aba0a02b90500b440cd218b0ea0048b16a2 }


condition:
	$a0
}