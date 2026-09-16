rule Win_Trojan_BAT_75
{
strings:
	$a0 = { 746674702e657865202d69 }

	$a1 = { 67657420646c2e657865 }

	$a2 = { 7374617274646c207374617274202f7720646c2e657865 }


condition:
	$a0 and $a1 and $a2
}