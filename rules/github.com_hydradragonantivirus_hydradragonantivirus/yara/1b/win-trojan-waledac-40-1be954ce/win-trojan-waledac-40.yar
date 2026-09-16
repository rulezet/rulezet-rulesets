rule Win_Trojan_Waledac_40
{
strings:
	$a0 = { 558bec83f3cd8d45e783c65733f803d88b15a9454400578d7a68682c }


condition:
	$a0
}