rule Win_Trojan_Morid_5
{
strings:
	$a0 = { be00??????56c3 }

	$a1 = { 83c64866813e58587501c3 }


condition:
	$a0 and $a1
}