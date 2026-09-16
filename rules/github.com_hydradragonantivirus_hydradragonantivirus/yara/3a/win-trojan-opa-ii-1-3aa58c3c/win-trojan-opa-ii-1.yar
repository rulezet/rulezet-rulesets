rule Win_Trojan_Opa_II_1
{
strings:
	$a0 = { 8b1e10011e0e1fba0001b958029c2eff1e08011fb8 }


condition:
	$a0
}