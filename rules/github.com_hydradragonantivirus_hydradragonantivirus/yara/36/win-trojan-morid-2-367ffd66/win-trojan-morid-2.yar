rule Win_Trojan_Morid_2
{
strings:
	$a0 = { ba00??????52c3 }

	$a1 = { 83c24866813a58587501c3 }


condition:
	$a0 and $a1
}