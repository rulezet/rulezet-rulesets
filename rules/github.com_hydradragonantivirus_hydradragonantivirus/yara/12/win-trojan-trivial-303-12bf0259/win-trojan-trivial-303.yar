rule Win_Trojan_Trivial_303
{
strings:
	$a0 = { b44ecd21721eba9e00b8013dcd218bd8b440b93400ba0001cd21b43ecd21b44fcd2173e2b409ba3601cd21 }


condition:
	$a0
}