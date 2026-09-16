rule Win_Trojan_Trivial_399
{
strings:
	$a0 = { b80157cd21b43ecd2159ba9e00b80143cd21b44febb7c3 }


condition:
	$a0
}