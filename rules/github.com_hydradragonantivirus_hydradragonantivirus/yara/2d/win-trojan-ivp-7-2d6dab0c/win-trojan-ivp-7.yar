rule Win_Trojan_IVP_7
{
strings:
	$a0 = { b94f012e8a366c022e8a2732e62e882743e2f5c3 }


condition:
	$a0
}