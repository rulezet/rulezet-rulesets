rule Win_Trojan_Trivial_257
{
strings:
	$a0 = { cd218bd8b92c00ba0001b440cd21b43ecd21b44febe0 }


condition:
	$a0
}