rule Win_Trojan_Trivial_136
{
strings:
	$a0 = { 1901b44ecd21ba9e00b8023dcd2193b440b11dba0001cd21cc }


condition:
	$a0
}