rule Win_Trojan_Trivial_273
{
strings:
	$a0 = { c9ba2701b44ecd21721bb8023dba9e00cd218bd8b12db440ba0001cd21b43ecd21b44febe1c3 }


condition:
	$a0
}