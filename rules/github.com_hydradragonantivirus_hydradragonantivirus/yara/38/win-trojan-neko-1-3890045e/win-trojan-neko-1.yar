rule Win_Trojan_Neko_1
{
strings:
	$a0 = { 9b0eb71323d923c2a81052f8bc101e0faaaf13a90810a450f88f106245a811473e9b1ea1133e9b }


condition:
	$a0
}