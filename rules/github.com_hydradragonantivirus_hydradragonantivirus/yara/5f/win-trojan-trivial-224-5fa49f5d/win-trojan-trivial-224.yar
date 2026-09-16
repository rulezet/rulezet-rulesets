rule Win_Trojan_Trivial_224
{
strings:
	$a0 = { b44ecd21b8023dba9e00cd218bd8b9280090ba0001b440cd21b43ecd21b44febe12a2e2a00 }


condition:
	$a0
}