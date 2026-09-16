rule Win_Trojan_Jet_1
{
strings:
	$a0 = { 0c02b5002e8a8eff01b80143cd211fc303d5b43feb1403d5b440eb0e33d2b80242eb0533d2 }


condition:
	$a0
}