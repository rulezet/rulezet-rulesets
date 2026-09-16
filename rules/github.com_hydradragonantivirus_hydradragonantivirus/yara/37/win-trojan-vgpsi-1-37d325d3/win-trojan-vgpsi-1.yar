rule Win_Trojan_Vgpsi_1
{
strings:
	$a0 = { 8bd5cd21b000e81d00b440b9c100ba0001cd21b002e80e00b440b9c1008bd5cd21b43e }


condition:
	$a0
}