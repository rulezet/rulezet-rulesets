rule Win_Trojan_Clonewar_3
{
strings:
	$a0 = { c3bad701b90000b8003dcd21c3bad70133c9b43ccd2172538bd8b9c800ba0001b440cd21b43e }


condition:
	$a0
}