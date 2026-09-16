rule Win_Trojan_E_29
{
strings:
	$a0 = { b80103e86000e86400061f8db756018d7f06b90900f3a533c0803c007403b856568d7f60b9 }


condition:
	$a0
}