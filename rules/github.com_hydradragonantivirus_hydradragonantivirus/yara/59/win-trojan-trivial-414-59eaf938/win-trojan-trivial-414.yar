rule Win_Trojan_Trivial_414
{
strings:
	$a0 = { 8a1e8000c687810000b8023dba8200cd219387f2b440b11bcd21c3 }


condition:
	$a0
}