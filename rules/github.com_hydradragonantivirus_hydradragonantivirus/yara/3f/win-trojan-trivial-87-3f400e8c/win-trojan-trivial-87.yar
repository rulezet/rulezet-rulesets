rule Win_Trojan_Trivial_87
{
strings:
	$a0 = { 4f3c8040ad998ad0d1e22a2e2a00cd2193eb }


condition:
	$a0
}