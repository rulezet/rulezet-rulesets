rule Win_Trojan_Trivial_89
{
strings:
	$a0 = { 4e4f3c80402a2e2a00ad998ad0d1e2cd21ebeb }


condition:
	$a0
}