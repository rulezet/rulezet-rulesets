rule Win_Trojan_Trivial_116
{
strings:
	$a0 = { 4eba1001cd21b43cba9e00cd21b21b2a2e434f4d0000000000f199211a00 }


condition:
	$a0
}