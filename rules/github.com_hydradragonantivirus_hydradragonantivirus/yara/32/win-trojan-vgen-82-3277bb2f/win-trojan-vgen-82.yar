rule Win_Trojan_Vgen_82
{
strings:
	$a0 = { 213c017f02cd20be2b01b98003b2ffb3003012301afecafec3fec345e2f3be8000803c0a7202cd2047f5cc37d2 }


condition:
	$a0
}