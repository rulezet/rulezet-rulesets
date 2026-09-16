rule Win_Trojan_Trivial_129
{
strings:
	$a0 = { 2187c3b44083c262cd21c32a2e632a }


condition:
	$a0
}