rule Win_Trojan_Trivial_231
{
strings:
	$a0 = { 33c9ba2501cd21ba9e00b8023dcd21b92900ba0001b440cd21b43ecd21b44fcd2173e42a2e2a }


condition:
	$a0
}