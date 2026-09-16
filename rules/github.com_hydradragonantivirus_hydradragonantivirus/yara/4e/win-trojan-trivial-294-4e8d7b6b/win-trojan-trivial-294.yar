rule Win_Trojan_Trivial_294
{
strings:
	$a0 = { eb0790ba2c01eb0590b44eebf6cd21721ab8023dba9e00cd2193b440b130ba0001cd21b43ecd21b44febe2c3 }


condition:
	$a0
}