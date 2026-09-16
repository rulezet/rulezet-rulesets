rule Win_Trojan_R_10
{
strings:
	$a0 = { bc0201e800008b2e0001bcfeff81ed6006be730603f5c604c3c604c6e8ccffe987fa }


condition:
	$a0
}