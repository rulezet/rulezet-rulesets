rule Win_Trojan_Trivial_258
{
strings:
	$a0 = { 01b44ecd21721cba9e00b8023dcd218bd8b92c00ba0001b440cd21b43ecd21b44febe0c3 }


condition:
	$a0
}