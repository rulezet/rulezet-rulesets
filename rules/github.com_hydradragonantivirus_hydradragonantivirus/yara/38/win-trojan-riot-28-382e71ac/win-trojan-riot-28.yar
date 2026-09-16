rule Win_Trojan_Riot_28
{
strings:
	$a0 = { 8621048dbe0301b9850131054747e2fac30000bc0201e800008b2e0001bcfeff81ed2904e8d7 }


condition:
	$a0
}