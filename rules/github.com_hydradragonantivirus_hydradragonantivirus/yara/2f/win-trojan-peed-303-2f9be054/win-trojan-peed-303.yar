rule Win_Trojan_Peed_303
{
strings:
	$a0 = { 558bec83ec10535657 }

	$a1 = { 41ff45fc3b4df0894df87c }


condition:
	$a0 and $a1
}