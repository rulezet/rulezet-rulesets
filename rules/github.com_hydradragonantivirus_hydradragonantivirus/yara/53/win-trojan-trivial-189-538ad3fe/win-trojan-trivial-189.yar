rule Win_Trojan_Trivial_189
{
strings:
	$a0 = { b440cd21b43ecd21cd202a2e2a00 }


condition:
	$a0
}