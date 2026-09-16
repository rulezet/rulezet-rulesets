rule Win_Trojan_LightGeneral_2
{
strings:
	$a0 = { b440ba7805cd21b80157268b4d0d268b550fcd21b43ecd21c3ba0001b99004b440cd2133d2 }


condition:
	$a0
}