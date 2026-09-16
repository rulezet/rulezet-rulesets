rule Win_Trojan_Trivial_271
{
strings:
	$a0 = { c9ba2701b44ecd21721bba9e00b8023dcd218bd8b12db440ba0001cd21b43ecd21b44febe1c32a2e43 }


condition:
	$a0
}