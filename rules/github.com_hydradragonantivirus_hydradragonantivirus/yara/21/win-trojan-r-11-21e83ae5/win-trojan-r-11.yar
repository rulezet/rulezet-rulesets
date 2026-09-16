rule Win_Trojan_R_11
{
strings:
	$a0 = { 0201e800008b2e0001bcfeff81ed6606be790603f5c604c3c604c6e8ccffe981fae9 }


condition:
	$a0
}