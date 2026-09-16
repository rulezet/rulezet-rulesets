rule Win_Trojan_VCL_32
{
strings:
	$a0 = { 01b91603b6682e8a2732e62e882743e2f5c3 }


condition:
	$a0
}