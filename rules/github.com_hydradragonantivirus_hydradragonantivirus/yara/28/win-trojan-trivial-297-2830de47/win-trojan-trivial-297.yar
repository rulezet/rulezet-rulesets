rule Win_Trojan_Trivial_297
{
strings:
	$a0 = { 01b44ecd21e80200cd20721dba9e00b8013dcd2193b440b93200ba0001cd21b43ecd21b44fcd2173e1c3 }


condition:
	$a0
}