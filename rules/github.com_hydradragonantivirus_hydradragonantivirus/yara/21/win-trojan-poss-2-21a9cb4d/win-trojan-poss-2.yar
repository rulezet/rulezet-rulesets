rule Win_Trojan_Poss_2
{
strings:
	$a0 = { ba0000b440e8af0172de8b0e62008e1e6400ba0000 }


condition:
	$a0
}