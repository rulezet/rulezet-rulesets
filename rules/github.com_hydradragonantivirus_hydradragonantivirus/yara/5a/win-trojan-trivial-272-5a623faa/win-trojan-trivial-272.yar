rule Win_Trojan_Trivial_272
{
strings:
	$a0 = { b44ecd21721db8023dba9e00cd218bd8b12dba0001b440cd21b43ecd21b44fcd21ebe1c3 }


condition:
	$a0
}