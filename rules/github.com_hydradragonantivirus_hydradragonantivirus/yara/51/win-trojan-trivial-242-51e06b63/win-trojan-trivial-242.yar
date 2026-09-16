rule Win_Trojan_Trivial_242
{
strings:
	$a0 = { c9ba2501cd21b8023dba9e00cd21b92a00ba0001b440cd21b43ecd21b44fcd2173e4 }


condition:
	$a0
}