rule Win_Trojan_R_8
{
strings:
	$a0 = { 01e800008b2e0001bcfeff81edfc05be0f0603f5c604c3c604c6e8ccffe9ebfa }


condition:
	$a0
}