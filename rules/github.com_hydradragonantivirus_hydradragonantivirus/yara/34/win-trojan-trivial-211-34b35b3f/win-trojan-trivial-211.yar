rule Win_Trojan_Trivial_211
{
strings:
	$a0 = { b440cd21b43ecd21b44febe22a2e2a00 }


condition:
	$a0
}