rule Win_Trojan_Onlinegames_26
{
strings:
	$a0 = { 63746d31323030342e657865 }

	$a1 = { 78796d61696e2e62696e }

	$a2 = { 420049004e }

	$a3 = { 67616d652e657865 }


condition:
	$a0 and $a1 and $a2 and $a3
}