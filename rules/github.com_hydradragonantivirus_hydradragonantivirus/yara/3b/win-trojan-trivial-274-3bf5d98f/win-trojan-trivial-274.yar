rule Win_Trojan_Trivial_274
{
strings:
	$a0 = { ba2901b44ecd21721eba9e00b8013dcd218bd8b440b92d00ba0001cd21b43ecd21b44fcd21ebe0 }


condition:
	$a0
}