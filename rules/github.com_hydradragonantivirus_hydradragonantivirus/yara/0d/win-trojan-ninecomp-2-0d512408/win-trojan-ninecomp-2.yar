rule Win_Trojan_Ninecomp_2
{
strings:
	$a0 = { e800005bbe110003f3b9aa0289f7ac30d8aae2fa }


condition:
	$a0
}