rule Win_Trojan_Trivial_254
{
strings:
	$a0 = { 434f4d0000565ab44e33c9cd21721983ea62b8013dcd2193b440b12b565acd21b43ecd21b44febe1c3 }


condition:
	$a0
}