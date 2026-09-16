rule Win_Trojan_Liquid_2
{
strings:
	$a0 = { 81c20102e83fffb80040cd2172dcba0000b90000b802 }


condition:
	$a0
}