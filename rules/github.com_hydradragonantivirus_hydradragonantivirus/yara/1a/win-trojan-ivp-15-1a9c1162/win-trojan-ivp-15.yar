rule Win_Trojan_IVP_15
{
strings:
	$a0 = { 9e1401b9a5022e8ab6d1032e8a2732e62e882743e2f5c3 }


condition:
	$a0
}