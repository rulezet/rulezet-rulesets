rule Win_Trojan_Lineage_435
{
strings:
	$a0 = { 3267763463366674387264307873657739617a7100000000 }


condition:
	$a0
}