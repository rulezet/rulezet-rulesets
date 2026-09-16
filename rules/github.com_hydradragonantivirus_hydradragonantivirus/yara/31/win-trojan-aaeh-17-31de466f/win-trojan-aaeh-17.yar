rule Win_Trojan_AAEH_17
{
strings:
	$a0 = { 2d433030302d736975786a62 }

	$a1 = { 49450b286a6161615f4b2f4e6d6eb7b9b95057e5e4bce5e8ce23000000000000000000000000dbfafafffc414841052d }


condition:
	$a0 and $a1
}