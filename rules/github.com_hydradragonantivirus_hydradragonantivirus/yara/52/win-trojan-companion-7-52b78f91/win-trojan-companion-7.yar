rule Win_Trojan_Companion_7
{
strings:
	$a0 = { 9b32d2cd21b40e0d0a30cd21b44a33f68d5c1dcd21 }


condition:
	$a0
}