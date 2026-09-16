rule Win_Trojan_Small_4227
{
strings:
	$a0 = { eb00e8b5000000e92e01000064ff350000000051 }


condition:
	$a0
}