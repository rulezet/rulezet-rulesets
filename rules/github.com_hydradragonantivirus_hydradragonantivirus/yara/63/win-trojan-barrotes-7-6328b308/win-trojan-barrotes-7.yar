rule Win_Trojan_Barrotes_7
{
strings:
	$a0 = { cd213deeff7503e9dd0006b82135cd212e891c2e8c }


condition:
	$a0
}