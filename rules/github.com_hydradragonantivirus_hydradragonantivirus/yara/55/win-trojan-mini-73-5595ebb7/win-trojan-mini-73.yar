rule Win_Trojan_Mini_73
{
strings:
	$a0 = { cd21803ce9741bb002e81b0097b133b440cd21b000e80f00c604e9897c01b440cd21b43ecd21 }


condition:
	$a0
}