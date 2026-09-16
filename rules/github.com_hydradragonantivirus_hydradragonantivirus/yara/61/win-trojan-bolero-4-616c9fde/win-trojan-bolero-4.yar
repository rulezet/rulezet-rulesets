rule Win_Trojan_Bolero_4
{
strings:
	$a0 = { 7d024d7501f9c350565751531e069cb462cd21531fa12c00501f33f646803c0175fa464646 }


condition:
	$a0
}