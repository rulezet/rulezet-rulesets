rule Win_Trojan_Flavour_5
{
strings:
	$a0 = { e800005e908d5c0f90b9cb038037??43e2fa }


condition:
	$a0
}