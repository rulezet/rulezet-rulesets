rule Win_Trojan_Trivial_471
{
strings:
	$a0 = { 2601b44ecd21721cba9e00b8023dcd218bd8b92c00ba0001b440cd21b43ecd21b44febe0c32a2e }


condition:
	$a0
}