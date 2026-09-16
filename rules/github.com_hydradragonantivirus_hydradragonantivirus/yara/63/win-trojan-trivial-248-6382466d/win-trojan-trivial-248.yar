rule Win_Trojan_Trivial_248
{
strings:
	$a0 = { 2401b44ecd21721ab8013dba9e00cd2193b440b12aba0001cd21b43ecd21b44febe2c32a2e636f }


condition:
	$a0
}