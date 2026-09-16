rule Win_Trojan_Trivial_225
{
strings:
	$a0 = { 01b440cd21b43ecd21b44febe12a2e2a00 }


condition:
	$a0
}