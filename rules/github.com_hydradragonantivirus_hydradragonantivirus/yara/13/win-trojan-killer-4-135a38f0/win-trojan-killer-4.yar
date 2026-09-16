rule Win_Trojan_Killer_4
{
strings:
	$a0 = { 5356573300000000ffffffff08000000426c61636b49434500000000ffffffff }


condition:
	$a0
}