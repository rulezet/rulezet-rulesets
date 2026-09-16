rule Win_Trojan_Trivial_135
{
strings:
	$a0 = { 1901b44ecd21ba9e00b8023dcd2193b440b11dba0001cd212a2e }


condition:
	$a0
}