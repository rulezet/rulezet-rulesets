rule Win_Trojan_VGEN_795
{
strings:
	$a0 = { 01b409cd21b4c0cd15268a4702ba??013cff7426ba??013cfe741fba??013cfd7418ba??013cfc7411ba??013cf9 }


condition:
	$a0
}