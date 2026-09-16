rule Win_Trojan_VCL_31
{
strings:
	$a0 = { 01b97f022e8ab6ae032e8a2732e62e882743e2f5c3 }


condition:
	$a0
}