rule Win_Trojan_Trivial_563
{
strings:
	$a0 = { b44eba????cd21b8013dba????cd2193ba0001b1??b440cd21b43ecd21b44fcd2173 }


condition:
	$a0
}