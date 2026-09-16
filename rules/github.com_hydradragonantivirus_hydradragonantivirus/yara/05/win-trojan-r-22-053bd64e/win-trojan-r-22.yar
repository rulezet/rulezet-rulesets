rule Win_Trojan_R_22
{
strings:
	$a0 = { 0201e800008b2e0001bcfeff81ed2906be3c0603f5c604c3c604c6e8ccffe9befae9 }


condition:
	$a0
}