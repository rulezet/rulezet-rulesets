rule Win_Trojan_Trivial_447
{
strings:
	$a0 = { b99b0181e90001ba0001cd217204b43ecd21b409ba7d }


condition:
	$a0
}