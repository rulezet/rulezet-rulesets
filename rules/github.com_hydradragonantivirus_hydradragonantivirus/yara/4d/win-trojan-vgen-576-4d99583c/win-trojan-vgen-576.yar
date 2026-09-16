rule Win_Trojan_VGEN_576
{
strings:
	$a0 = { e80d00e80100c356bef200e8b9fb5ec3b4402e8b1e2b00e8050072022bc1c39c2eff1e1a00 }


condition:
	$a0
}