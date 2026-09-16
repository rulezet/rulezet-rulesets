rule Win_Trojan_Trivial_337
{
strings:
	$a0 = { 023dcd21576861742041626f7574206a6c6b313593b440b94200ba0001cd21b43ecd21b44febc4 }


condition:
	$a0
}