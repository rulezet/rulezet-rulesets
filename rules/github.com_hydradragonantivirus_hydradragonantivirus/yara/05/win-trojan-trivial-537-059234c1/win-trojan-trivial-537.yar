rule Win_Trojan_Trivial_537
{
strings:
	$a0 = { b44eba000152cd21b8013dba????cd2193b4405acd21c3 }


condition:
	$a0
}