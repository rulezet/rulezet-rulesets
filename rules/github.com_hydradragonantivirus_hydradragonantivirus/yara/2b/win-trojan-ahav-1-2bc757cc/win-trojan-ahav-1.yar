rule Win_Trojan_AHaV_1
{
strings:
	$a0 = { 028db60f01eb07ad33c2abe2fac3b98b008bfeebf2 }


condition:
	$a0
}