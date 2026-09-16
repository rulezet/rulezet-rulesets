rule Win_Trojan_Peed_134
{
strings:
	$a0 = { 60e8 }

	$a1 = { 61ffe055545df3cd2ab8d90caefd }


condition:
	$a0 and $a1
}