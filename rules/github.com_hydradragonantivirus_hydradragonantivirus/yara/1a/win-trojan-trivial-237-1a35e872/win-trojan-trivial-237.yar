rule Win_Trojan_Trivial_237
{
strings:
	$a0 = { b44eba2501cd21721ab8023dba9e00cd2193b440b12aba0001cd21b43ecd21b44febe2cd20 }


condition:
	$a0
}