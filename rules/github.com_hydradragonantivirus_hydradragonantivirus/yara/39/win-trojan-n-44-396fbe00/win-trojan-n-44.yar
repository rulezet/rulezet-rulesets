rule Win_Trojan_N_44
{
strings:
	$a0 = { 04f406c7470670002ec606ef05ebb88046cd2f85c074062ec606ef0575ba8000520e0e1f07 }


condition:
	$a0
}