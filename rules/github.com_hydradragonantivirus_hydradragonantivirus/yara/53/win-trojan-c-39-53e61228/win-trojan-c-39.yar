rule Win_Trojan_C_39
{
strings:
	$a0 = { 028db60301b9b40031044646e2fac35004bc0201e8 }


condition:
	$a0
}