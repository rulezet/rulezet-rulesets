rule Win_Trojan_Trivial_241
{
strings:
	$a0 = { 2601b44e33c9cd21721aba9e00b8013dcd2193b440b12aba0001cd21b43ecd21b44febe0c32a2e2a00 }


condition:
	$a0
}