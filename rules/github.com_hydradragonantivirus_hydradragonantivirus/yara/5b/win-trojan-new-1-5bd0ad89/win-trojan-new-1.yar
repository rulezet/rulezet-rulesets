rule Win_Trojan_New_1
{
strings:
	$a0 = { ff2e2a00b440eb02b43fe8090072023b }


condition:
	$a0
}